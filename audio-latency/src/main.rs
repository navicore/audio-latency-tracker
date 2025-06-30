use anyhow::{Context, Result};
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{tc, TcAttachType, SchedClassifier},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
mod config;
mod signature;
mod metrics;
mod container;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::{signal, sync::mpsc, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    
    #[clap(short, long, default_value = "info")]
    log_level: String,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AudioEvent {
    timestamp: u64,
    signature: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    pid: u32,
}

struct LatencyTracker {
    signatures: HashMap<u32, Vec<(u64, String)>>,
}

impl LatencyTracker {
    fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }
    
    fn process_event(&mut self, event: AudioEvent) {
        let src = format!(
            "{}:{}", 
            Ipv4Addr::from(event.src_ip),
            event.src_port
        );
        let dst = format!(
            "{}:{}",
            Ipv4Addr::from(event.dst_ip),
            event.dst_port
        );
        
        let entry = self.signatures.entry(event.signature).or_insert_with(Vec::new);
        
        // Check if we've seen this signature before
        if !entry.is_empty() {
            let first_seen = entry[0].0;
            let latency_ns = event.timestamp - first_seen;
            let latency_ms = latency_ns as f64 / 1_000_000.0;
            
            info!(
                "Signature {} latency: {:.2}ms (from {} to {} -> {})",
                event.signature,
                latency_ms,
                entry[0].1,
                src,
                dst
            );
        }
        
        entry.push((event.timestamp, format!("{} -> {}", src, dst)));
        
        // Keep only last 10 occurrences of each signature
        if entry.len() > 10 {
            entry.remove(0);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&opt.log_level))
        .init();
    
    // Load eBPF program
    let data = std::fs::read("target/bpf/audio-latency-ebpf")
        .context("Failed to read eBPF program - run 'make build-ebpf' first")?;
    let mut ebpf = Ebpf::load(&data)?;
    
    // Initialize eBPF logger
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    
    // Attach TC program
    let program: &mut SchedClassifier = ebpf.program_mut("tc_ingress").unwrap().try_into()?;
    program.load()?;
    
    // Get interface index
    let _iface_idx = get_interface_index(&opt.iface)?;
    
    // Create TC qdisc if it doesn't exist
    if let Err(_) = tc::qdisc_add_clsact(&opt.iface) {
        debug!("clsact qdisc already exists on {}", opt.iface);
    }
    
    program.attach(&opt.iface, TcAttachType::Ingress)
        .context("Failed to attach TC program")?;
    
    info!("Attached TC program to interface {}", opt.iface);
    
    // Set up perf event array
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("AUDIO_EVENTS").unwrap())?;
    
    let mut tracker = LatencyTracker::new();
    
    // Process events from all CPUs
    let (tx, mut rx) = mpsc::channel::<AudioEvent>(1000);
    
    for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            
            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        warn!("Error reading events: {}", e);
                        continue;
                    }
                };
                
                for buf in buffers.iter().take(events.read) {
                    let ptr = buf.as_ptr() as *const AudioEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    
                    if let Err(e) = tx.send(event).await {
                        warn!("Failed to send event: {}", e);
                    }
                }
            }
        });
    }
    
    // Drop original sender so rx.recv() can return None when all tasks complete
    drop(tx);
    
    // Process events in main task
    let _process_task = task::spawn(async move {
        while let Some(event) = rx.recv().await {
            tracker.process_event(event);
        }
    });
    
    info!("Waiting for audio events... Press Ctrl-C to stop.");
    signal::ctrl_c().await?;
    info!("Exiting...");
    
    Ok(())
}

fn get_interface_index(name: &str) -> Result<u32> {
    use std::ffi::CString;
    use std::os::raw::c_char;
    
    let c_name = CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr() as *const c_char) };
    
    if index == 0 {
        anyhow::bail!("Interface {} not found", name);
    }
    
    Ok(index)
}