use anyhow::{Context, Result};
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::{signal, sync::mpsc, task};
use tracing::{debug, info, warn};

mod config;
mod metrics;
mod network_discovery;
mod pod_watcher;

use config::Config;
use metrics::MetricsCollector;
use network_discovery::NetworkTopology;
use pod_watcher::{PodCache, PodWatcher};

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
}

struct LatencyTracker {
    signatures: HashMap<u32, Vec<(u64, String, String)>>, // (timestamp, source, destination)
    metrics: MetricsCollector,
    pod_cache: PodCache,
}

impl LatencyTracker {
    fn new(_config: &Config, metrics: MetricsCollector, pod_cache: PodCache) -> Self {
        Self {
            signatures: HashMap::new(),
            metrics,
            pod_cache,
        }
    }

    async fn process_event(&mut self, event: AudioEvent, interface: &str, node_name: &str) {
        let src_ip = Ipv4Addr::from(event.src_ip).to_string();
        let dst_ip = Ipv4Addr::from(event.dst_ip).to_string();

        // Look up pod information
        use std::str::FromStr;
        let src_ip_addr = std::net::IpAddr::from_str(&src_ip).ok();
        let dst_ip_addr = std::net::IpAddr::from_str(&dst_ip).ok();

        let src_pod = if let Some(ip) = src_ip_addr {
            let pod = self.pod_cache.get(&ip).await;
            if pod.is_none() {
                debug!("No pod found for source IP: {}", ip);
            }
            pod
        } else {
            None
        };

        let dst_pod = if let Some(ip) = dst_ip_addr {
            let pod = self.pod_cache.get(&ip).await;
            if pod.is_none() {
                debug!("No pod found for destination IP: {}", ip);
            }
            pod
        } else {
            None
        };

        // Calculate timestamp before JSON creation
        let now = chrono::Utc::now();
        let timestamp_human = now.format("%Y-%m-%dT%H:%M:%S.%9fZ").to_string();

        // Log as structured event with pod information (use "unknown" for missing data)
        info!(
            event_type = "audio_signature",
            timestamp_ns = event.timestamp,
            signature = event.signature,
            node = node_name,
            interface = interface,
            src_ip = %src_ip,
            src_port = event.src_port,
            src_pod = src_pod.as_ref().map(|p| p.pod_name.as_str()).unwrap_or("unknown"),
            src_namespace = src_pod.as_ref().map(|p| p.namespace.as_str()).unwrap_or("unknown"),
            src_workload = src_pod.as_ref().map(|p| format!("{}/{}", p.workload_kind, p.workload_name)).unwrap_or_else(|| "unknown".to_string()),
            dst_ip = %dst_ip,
            dst_port = event.dst_port,
            dst_pod = dst_pod.as_ref().map(|p| p.pod_name.as_str()).unwrap_or("unknown"),
            dst_namespace = dst_pod.as_ref().map(|p| p.namespace.as_str()).unwrap_or("unknown"),
            dst_workload = dst_pod.as_ref().map(|p| format!("{}/{}", p.workload_kind, p.workload_name)).unwrap_or_else(|| "unknown".to_string()),
            timestamp_human = %timestamp_human,
            "Audio signature detected"
        );

        // Also update metrics for general monitoring (not per-signature)
        self.metrics.record_signature(&src_ip, event.src_port);

        // Keep local tracking for immediate feedback (optional)
        let entry = self.signatures.entry(event.signature).or_default();
        if !entry.is_empty() {
            let first_seen = entry[0].0;
            let latency_ns = event.timestamp - first_seen;
            let latency_ms = latency_ns as f64 / 1_000_000.0;

            debug!(
                event_type = "latency_calculation",
                signature = event.signature,
                latency_ms = latency_ms,
                "Local latency calculation: signature seen again"
            );
        }
        entry.push((
            event.timestamp,
            format!("{node_name}/{interface}"),
            format!("{src_ip}:{}", event.src_port),
        ));

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

    // Initialize JSON logging
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    info!(
        event_type = "startup",
        interface = %interface,
        signature_algorithm = ?config.signature_algorithm,
        k8s_enabled = config.k8s_enabled,
        "Starting audio latency tracker"
    );

    // Discover network topology
    let network_topology = NetworkTopology::discover().unwrap_or_else(|e| {
        warn!(
            event_type = "network_discovery_error",
            error = %e,
            "Failed to discover network topology"
        );
        // Return minimal topology
        NetworkTopology {
            interfaces: Vec::new(),
            routes: Vec::new(),
            default_interface: Some("eth0".to_string()),
            pod_interfaces: vec!["eth0".to_string()],
        }
    });

    // Initialize metrics collector
    let metrics = MetricsCollector::new();
    let metrics_clone = metrics.clone();

    // Start metrics server
    let metrics_port = config.metrics_port;
    task::spawn(async move {
        if let Err(e) = metrics_clone.start_server(metrics_port).await {
            warn!(
                event_type = "metrics_server_error",
                error = %e,
                "Failed to start metrics server"
            );
        }
    });

    // Initialize pod watcher if Kubernetes is enabled
    let pod_cache = if config.k8s_enabled {
        match PodWatcher::new().await {
            Ok(watcher) => {
                let cache = watcher.cache().clone();
                task::spawn(async move {
                    if let Err(e) = watcher.start().await {
                        warn!(
                            event_type = "pod_watcher_error",
                            error = %e,
                            "Pod watcher failed"
                        );
                    }
                });
                info!(
                    event_type = "pod_watcher_started",
                    "Kubernetes pod watcher started"
                );
                cache
            }
            Err(e) => {
                warn!(
                    event_type = "pod_watcher_init_error",
                    error = %e,
                    "Failed to initialize pod watcher, continuing without Kubernetes enrichment"
                );
                PodCache::new()
            }
        }
    } else {
        info!(
            event_type = "pod_watcher_disabled",
            "Kubernetes integration disabled"
        );
        PodCache::new()
    };

    // Load eBPF program
    let data =
        std::fs::read("target/bpf/audio-latency-ebpf").context("Failed to read eBPF program")?;
    let mut ebpf = Ebpf::load(&data)?;

    // Initialize eBPF logger
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!(
            event_type = "ebpf_logger_error",
            error = %e,
            "Failed to initialize eBPF logger"
        );
    }

    // Set configuration in eBPF map
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AudioConfig {
        min_packet_size: u32,
    }

    unsafe impl aya::Pod for AudioConfig {}

    let audio_config = AudioConfig {
        min_packet_size: config.min_audio_packet_size,
    };

    let mut config_map: aya::maps::Array<_, AudioConfig> =
        aya::maps::Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;
    config_map.set(0, audio_config, 0)?;

    info!(
        event_type = "ebpf_config_set",
        min_audio_packet_size = config.min_audio_packet_size,
        "Configured eBPF with minimum audio packet size"
    );

    // TODO: Configure port filtering if specified
    if let Some(ref ports) = config.audio_ports {
        debug!(
            event_type = "port_filter_configured",
            ports = ?ports,
            "Port filtering configured (not yet implemented in eBPF)"
        );
        // This would require adding a map to the eBPF program for port filtering
    }

    // Load TC programs
    {
        let ingress_program: &mut SchedClassifier =
            ebpf.program_mut("tc_ingress").unwrap().try_into()?;
        ingress_program.load()?;
    }

    {
        let egress_program: &mut SchedClassifier =
            ebpf.program_mut("tc_egress").unwrap().try_into()?;
        egress_program.load()?;
    }

    // Get interfaces to monitor - use discovered pod interfaces or fallback to CLI/config
    let interfaces_to_monitor = if !network_topology.pod_interfaces.is_empty() {
        network_topology.pod_interfaces.clone()
    } else {
        vec![interface.to_string()]
    };

    info!(
        event_type = "interfaces_selected",
        interfaces = ?interfaces_to_monitor,
        "Selected interfaces for monitoring"
    );

    // Attach to all selected interfaces (both ingress and egress)
    let mut attached_interfaces = Vec::new();
    for iface in &interfaces_to_monitor {
        // Verify interface exists
        if let Err(e) = get_interface_index(iface) {
            warn!(
                event_type = "interface_not_found",
                interface = %iface,
                error = %e,
                "Skipping interface - not found"
            );
            continue;
        }

        // Create TC qdisc if it doesn't exist
        if tc::qdisc_add_clsact(iface).is_err() {
            debug!(
                event_type = "qdisc_exists",
                interface = %iface,
                "clsact qdisc already exists"
            );
        }

        let mut interface_attached = false;

        // Attach ingress program to interface
        {
            let ingress_program: &mut SchedClassifier =
                ebpf.program_mut("tc_ingress").unwrap().try_into()?;
            if let Err(e) = ingress_program.attach(iface, TcAttachType::Ingress) {
                warn!(
                    event_type = "tc_ingress_attach_failed",
                    interface = %iface,
                    error = %e,
                    "Failed to attach TC ingress program to interface"
                );
            } else {
                interface_attached = true;
                info!(
                    event_type = "tc_ingress_attached",
                    interface = %iface,
                    "Successfully attached TC ingress program to interface"
                );
            }
        }

        // Attach egress program to interface
        {
            let egress_program: &mut SchedClassifier =
                ebpf.program_mut("tc_egress").unwrap().try_into()?;
            if let Err(e) = egress_program.attach(iface, TcAttachType::Egress) {
                warn!(
                    event_type = "tc_egress_attach_failed",
                    interface = %iface,
                    error = %e,
                    "Failed to attach TC egress program to interface"
                );
            } else {
                interface_attached = true;
                info!(
                    event_type = "tc_egress_attached",
                    interface = %iface,
                    "Successfully attached TC egress program to interface"
                );
            }
        }

        if interface_attached {
            attached_interfaces.push(iface.clone());
        }
    }

    if attached_interfaces.is_empty() {
        anyhow::bail!("Failed to attach TC program to any interface");
    }

    info!(
        event_type = "tc_attachment_complete",
        attached_interfaces = ?attached_interfaces,
        "TC programs (ingress/egress) attached to all available interfaces"
    );

    // Set up perf event array
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("AUDIO_EVENTS").unwrap())?;

    let mut tracker = LatencyTracker::new(&config, metrics, pod_cache);

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
                        warn!(
                            event_type = "event_read_error",
                            error = %e,
                            "Error reading events"
                        );
                        continue;
                    }
                };

                for buf in buffers.iter().take(events.read) {
                    let ptr = buf.as_ptr() as *const AudioEvent;
                    let event = unsafe { ptr.read_unaligned() };

                    if let Err(e) = tx.send(event).await {
                        warn!(
                            event_type = "event_send_error",
                            error = %e,
                            "Failed to send event"
                        );
                    }
                }
            }
        });
    }

    // Drop original sender so rx.recv() can return None when all tasks complete
    drop(tx);

    // Get node name from environment or hostname
    let node_name = config.k8s_node_name.clone().unwrap_or_else(|| {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    });

    let interfaces_summary = attached_interfaces.join(",");

    // Process events in main task
    let process_task = task::spawn(async move {
        while let Some(event) = rx.recv().await {
            tracker
                .process_event(event, &interfaces_summary, &node_name)
                .await;
        }
    });

    info!(
        event_type = "startup_complete",
        "Audio latency tracker started successfully"
    );
    info!(
        "Metrics available at http://0.0.0.0:{}/metrics",
        config.metrics_port
    );
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
