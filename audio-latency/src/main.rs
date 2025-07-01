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
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::{signal, sync::mpsc, task};

mod config;
mod metrics;

use config::Config;
use metrics::MetricsCollector;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    iface: Option<String>,
    
    #[clap(short, long)]
    log_level: Option<String>,
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
    signatures: HashMap<u32, Vec<(u64, String, String)>>, // (timestamp, source, destination)
    metrics: MetricsCollector,
}

impl LatencyTracker {
    fn new(_config: &Config, metrics: MetricsCollector) -> Self {
        Self {
            signatures: HashMap::new(),
            metrics,
        }
    }
    
    async fn process_event(&mut self, event: AudioEvent, interface: &str, node_name: &str) {
        let src_ip = Ipv4Addr::from(event.src_ip).to_string();
        let dst_ip = Ipv4Addr::from(event.dst_ip).to_string();
        
        // Pod identification via IP lookup
        // TODO: Implement K8s pod watcher to maintain IP->Pod mapping
        let src_pod: Option<&str> = None;
        let dst_pod: Option<&str> = None;
        let direction = "unknown";
        
        // Calculate timestamp before JSON creation
        let now = chrono::Utc::now();
        let timestamp_human = now.format("%Y-%m-%dT%H:%M:%S.%9fZ").to_string();
        let pid = if event.pid > 0 { Some(event.pid) } else { None };
        
        // Log comprehensive JSON event for every signature sighting
        let event_json = serde_json::json!({
            "timestamp_ns": event.timestamp,
            "signature": event.signature,
            "node": node_name,
            "interface": interface,
            "direction": direction,
            "src": {
                "ip": src_ip,
                "port": event.src_port,
                "pod": src_pod,
            },
            "dst": {
                "ip": dst_ip,
                "port": event.dst_port,
                "pod": dst_pod,
            },
            "metadata": {
                "pid": pid,
                "timestamp_human": timestamp_human
            }
        });
        
        // Log as structured JSON
        info!("AUDIO_SIGNATURE_EVENT: {}", event_json);
        
        // Also update metrics for general monitoring (not per-signature)
        self.metrics.record_signature(&src_ip, event.src_port);
        
        // Keep local tracking for immediate feedback (optional)
        let entry = self.signatures.entry(event.signature).or_insert_with(Vec::new);
        if !entry.is_empty() {
            let first_seen = entry[0].0;
            let latency_ns = event.timestamp - first_seen;
            let latency_ms = latency_ns as f64 / 1_000_000.0;
            
            debug!(
                "Local latency calculation: signature {} seen again after {:.2}ms",
                event.signature,
                latency_ms
            );
        }
        entry.push((event.timestamp, format!("{}/{}", node_name, interface), direction.to_string()));
        
        // Keep only last 100 occurrences locally
        if entry.len() > 100 {
            entry.remove(0);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration from environment
    let config = Config::from_env()?;
    config.validate()?;
    
    // Override with CLI args if provided
    let opt = Opt::parse();
    let interface = opt.iface.as_ref().unwrap_or(&config.interface);
    let log_level = opt.log_level.as_ref().unwrap_or(&config.log_level);
    
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .init();
    
    info!("Starting audio latency tracker");
    info!("Configuration: interface={}, signature_algorithm={:?}, k8s_enabled={}", 
        interface, config.signature_algorithm, config.k8s_enabled);
    
    // Initialize metrics collector
    let metrics = MetricsCollector::new();
    let metrics_clone = metrics.clone();
    
    // Start metrics server
    let metrics_port = config.metrics_port;
    task::spawn(async move {
        if let Err(e) = metrics_clone.start_server(metrics_port).await {
            warn!("Failed to start metrics server: {}", e);
        }
    });
    
    // Load eBPF program
    let data = std::fs::read("target/bpf/audio-latency-ebpf")
        .context("Failed to read eBPF program")?;
    let mut ebpf = Ebpf::load(&data)?;
    
    // Initialize eBPF logger
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    
    // TODO: Configure port filtering if specified
    if let Some(ref ports) = config.audio_ports {
        debug!("Port filtering configured for: {:?}", ports);
        // This would require adding a map to the eBPF program for port filtering
    }
    
    // Attach TC program
    let program: &mut SchedClassifier = ebpf.program_mut("tc_ingress").unwrap().try_into()?;
    program.load()?;
    
    // Get interface index
    let _iface_idx = get_interface_index(interface)?;
    
    // Create TC qdisc if it doesn't exist
    if let Err(_) = tc::qdisc_add_clsact(interface) {
        debug!("clsact qdisc already exists on {}", interface);
    }
    
    program.attach(interface, TcAttachType::Ingress)
        .context("Failed to attach TC program")?;
    
    info!("Attached TC program to interface {}", interface);
    
    // Set up perf event array
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("AUDIO_EVENTS").unwrap())?;
    
    let mut tracker = LatencyTracker::new(&config, metrics);
    
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
    
    // Get node name from environment or hostname
    let node_name = config.k8s_node_name.clone()
        .unwrap_or_else(|| hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string()));
    
    let interface_clone = interface.to_string();
    
    // Process events in main task
    let process_task = task::spawn(async move {
        while let Some(event) = rx.recv().await {
            tracker.process_event(event, &interface_clone, &node_name).await;
        }
    });
    
    info!("Audio latency tracker started successfully");
    info!("Metrics available at http://0.0.0.0:{}/metrics", config.metrics_port);
    info!("Waiting for audio events... Press Ctrl-C to stop.");
    
    signal::ctrl_c().await?;
    info!("Shutting down...");
    
    // Cancel the process task
    process_task.abort();
    
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