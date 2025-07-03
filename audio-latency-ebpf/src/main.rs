#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{HashMap, PerfEventArray},
    programs::TcContext,
};
use aya_log_ebpf::{info, trace};
use core::mem;

// Manual struct definitions for network headers
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct IpHdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

impl IpHdr {
    fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }
}

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_res_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

impl TcpHdr {
    fn doff(&self) -> u8 {
        ((self.doff_res_flags.to_be() >> 12) & 0x0F) as u8
    }
}

// Event structure for userspace communication
#[repr(C)]
pub struct AudioEvent {
    pub timestamp: u64,
    pub signature: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

// Configuration structure
#[repr(C)]
pub struct AudioConfig {
    pub min_packet_size: u32,
}

// Maps
#[map]
static AUDIO_EVENTS: PerfEventArray<AudioEvent> = PerfEventArray::new(0);

#[map]
static FLOW_STATE: HashMap<u64, u32> = HashMap::with_max_entries(10240, 0);

#[map]
static CONFIG: aya_ebpf::maps::Array<AudioConfig> = aya_ebpf::maps::Array::with_max_entries(1, 0);

// Improved audio signature detection that distinguishes audio from encrypted data
#[inline(always)]
fn calculate_audio_signature(data: &[u8]) -> u32 {
    // Audio characteristics vs encrypted data:
    // 1. Audio has patterns - samples cluster around certain values
    // 2. Audio has temporal coherence - adjacent samples are similar
    // 3. Encrypted data is uniformly random

    let mut hash: u32 = 0;
    let mut i = 0;
    let mut non_silence_samples = 0;
    let mut total_diff = 0u32;
    let mut prev_sample = 0x8000u16; // Start with silence value

    // Analyze entropy and patterns in the data
    let mut byte_counts = [0u8; 16]; // Count occurrences of byte values (grouped)

    // Process audio as 16-bit PCM samples
    while i < data.len() && i < 256 {
        // Analyze more data for better detection
        if i + 1 < data.len() {
            let sample = (data[i] as u16) | ((data[i + 1] as u16) << 8);

            // Track byte distribution (for entropy check)
            byte_counts[(data[i] >> 4) as usize] =
                byte_counts[(data[i] >> 4) as usize].saturating_add(1);
            byte_counts[(data[i + 1] >> 4) as usize] =
                byte_counts[(data[i + 1] >> 4) as usize].saturating_add(1);

            // Check if sample is non-silence
            let distance_from_silence = sample.abs_diff(0x8000);
            if distance_from_silence > 256 {
                non_silence_samples += 1;

                // Calculate temporal difference (audio has smooth transitions)
                let sample_diff = sample.abs_diff(prev_sample);
                total_diff = total_diff.saturating_add(sample_diff as u32);

                // Update hash with sample value
                hash = hash.wrapping_mul(31).wrapping_add(sample as u32);
            }

            prev_sample = sample;
        }
        i += 2;
    }

    // Reject if too few non-silence samples (not real audio)
    if non_silence_samples < 10 {
        return 0;
    }

    // Calculate entropy - count how many byte groups were seen
    let mut entropy_score = 0;
    for count in byte_counts.iter() {
        if *count > 0 {
            entropy_score += 1;
        }
    }

    // Encrypted data will have high entropy (all byte values present)
    // Audio data will have moderate entropy (clustered values)
    if entropy_score > 14 {
        // Too random - likely encrypted
        return 0;
    }

    // Check temporal coherence - audio should have smooth transitions
    let avg_diff = total_diff / non_silence_samples.max(1);
    if avg_diff > 20000 {
        // Samples jumping wildly - likely encrypted
        return 0;
    }

    hash
}

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_ingress(ctx: TcContext) -> Result<i32, i64> {
    process_tcp_packet(ctx, "ingress")
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, i64> {
    process_tcp_packet(ctx, "egress")
}

fn process_tcp_packet(ctx: TcContext, direction: &str) -> Result<i32, i64> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| 1i64)?;

    // Only process IPv4 packets (0x0800 in network byte order)
    if eth_hdr.h_proto != 0x0008u16 {
        return Ok(TC_ACT_PIPE);
    }

    let ip_hdr: IpHdr = ctx.load(mem::size_of::<EthHdr>()).map_err(|_| 1i64)?;

    // Only process TCP packets
    if ip_hdr.protocol != 6 {
        return Ok(TC_ACT_PIPE);
    }

    let tcp_hdr_offset = mem::size_of::<EthHdr>() + (ip_hdr.ihl() * 4) as usize;
    let tcp_hdr: TcpHdr = ctx.load(tcp_hdr_offset).map_err(|_| 1i64)?;

    // Calculate payload offset
    let payload_offset = tcp_hdr_offset + (tcp_hdr.doff() * 4) as usize;

    // TRACE: Log all TCP packets we see with direction
    trace!(
        &ctx,
        "[{}] TCP packet: {}:{} -> {}:{} payload_len={}",
        direction,
        u32::from_be(ip_hdr.saddr),
        u16::from_be(tcp_hdr.source),
        u32::from_be(ip_hdr.daddr),
        u16::from_be(tcp_hdr.dest),
        ctx.len() as usize - payload_offset
    );

    // Try to read some payload data
    let payload_len = ctx.len() as usize - payload_offset;

    // Get minimum packet size from config (default to 256 if not set)
    let min_size = CONFIG.get(0).map(|cfg| cfg.min_packet_size).unwrap_or(256);

    // Audio packets are typically larger than control traffic
    if payload_len < min_size as usize {
        // TRACE: Log why we're skipping this packet
        trace!(
            &ctx,
            "[{}] Skipping packet (payload too small): {}:{} -> {}:{} payload_len={} min_required={}",
            direction,
            u32::from_be(ip_hdr.saddr),
            u16::from_be(tcp_hdr.source),
            u32::from_be(ip_hdr.daddr),
            u16::from_be(tcp_hdr.dest),
            payload_len,
            min_size
        );
        return Ok(TC_ACT_PIPE);
    }

    // Read payload data
    let mut buf = [0u8; 128];
    let read_len = core::cmp::min(payload_len, 128);

    for i in 0..read_len {
        buf[i] = ctx.load::<u8>(payload_offset + i).map_err(|_| 1i64)?;
    }

    // Calculate audio signature
    let signature = calculate_audio_signature(&buf[..read_len]);

    // Only report non-zero signatures (non-silence)
    if signature != 0 {
        let event = AudioEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            signature,
            src_ip: u32::from_be(ip_hdr.saddr),
            dst_ip: u32::from_be(ip_hdr.daddr),
            src_port: u16::from_be(tcp_hdr.source),
            dst_port: u16::from_be(tcp_hdr.dest),
        };

        AUDIO_EVENTS.output(&ctx, &event, 0);

        info!(
            &ctx,
            "[{}] Audio signature detected: {} from {}:{} to {}:{}",
            direction,
            signature,
            u32::from_be(ip_hdr.saddr),
            u16::from_be(tcp_hdr.source),
            u32::from_be(ip_hdr.daddr),
            u16::from_be(tcp_hdr.dest)
        );
    } else {
        // TRACE: Log packets that didn't generate signatures
        trace!(
            &ctx,
            "[{}] No signature (zero hash): {}:{} -> {}:{}",
            direction,
            u32::from_be(ip_hdr.saddr),
            u16::from_be(tcp_hdr.source),
            u32::from_be(ip_hdr.daddr),
            u16::from_be(tcp_hdr.dest)
        );
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
