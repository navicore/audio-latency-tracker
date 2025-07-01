use std::env;
use std::str::FromStr;
use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    // Core
    pub interface: String,
    pub log_level: String,
    pub metrics_port: u16,
    
    // Audio Processing
    pub audio_ports: Option<Vec<u16>>,
    pub signature_window_size: usize,
    
    /// PCM threshold for detecting silence in audio samples.
    /// Currently the eBPF program has this hardcoded, but once we implement
    /// dynamic configuration via eBPF maps, this will be used to filter out
    /// silent periods to avoid tracking non-audio data.
    /// TODO: Pass this to eBPF via a config map in v2
    #[allow(dead_code)]
    pub silence_threshold: u16,
    
    pub signature_algorithm: SignatureAlgorithm,
    
    // Kubernetes
    pub k8s_enabled: bool,
    pub k8s_node_name: Option<String>,
    
    // Performance
    pub max_flows: u32,
    
    /// Timeout in milliseconds for flow state entries in eBPF maps.
    /// This will be used when we implement stateful packet reassembly
    /// to handle audio data that spans multiple packets. The eBPF program
    /// will track partial signatures and expire them after this timeout.
    /// TODO: Implement stateful packet reassembly in v2
    #[allow(dead_code)]
    pub flow_timeout_ms: u64,
    
    pub perf_buffer_size: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    RollingHash,
    Crc32,
    XxHash,
}

impl FromStr for SignatureAlgorithm {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "rolling_hash" => Ok(SignatureAlgorithm::RollingHash),
            "crc32" => Ok(SignatureAlgorithm::Crc32),
            "xxhash" => Ok(SignatureAlgorithm::XxHash),
            _ => anyhow::bail!("Unknown signature algorithm: {}", s),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            // Core
            interface: env::var("INTERFACE").unwrap_or_else(|_| "eth0".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            metrics_port: env::var("METRICS_PORT")
                .unwrap_or_else(|_| "9090".to_string())
                .parse()
                .context("Invalid METRICS_PORT")?,
            
            // Audio Processing
            audio_ports: env::var("AUDIO_PORTS").ok().map(|s| {
                s.split(',')
                    .filter_map(|p| p.trim().parse::<u16>().ok())
                    .collect()
            }),
            signature_window_size: env::var("SIGNATURE_WINDOW_SIZE")
                .unwrap_or_else(|_| "256".to_string())
                .parse()
                .context("Invalid SIGNATURE_WINDOW_SIZE")?,
            silence_threshold: env::var("SILENCE_THRESHOLD")
                .unwrap_or_else(|_| "256".to_string())
                .parse()
                .context("Invalid SILENCE_THRESHOLD")?,
            signature_algorithm: env::var("SIGNATURE_ALGORITHM")
                .unwrap_or_else(|_| "xxhash".to_string())
                .parse()
                .context("Invalid SIGNATURE_ALGORITHM")?,
            
            // Kubernetes
            k8s_enabled: env::var("K8S_ENABLED")
                .unwrap_or_else(|_| {
                    // Auto-detect if we're in k8s by checking for service account
                    if std::path::Path::new("/var/run/secrets/kubernetes.io").exists() {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }
                })
                .parse()
                .unwrap_or(false),
            k8s_node_name: env::var("K8S_NODE_NAME").ok(),
            
            // Performance
            max_flows: env::var("MAX_FLOWS")
                .unwrap_or_else(|_| "10000".to_string())
                .parse()
                .context("Invalid MAX_FLOWS")?,
            flow_timeout_ms: env::var("FLOW_TIMEOUT_MS")
                .unwrap_or_else(|_| "30000".to_string())
                .parse()
                .context("Invalid FLOW_TIMEOUT_MS")?,
            perf_buffer_size: env::var("PERF_BUFFER_SIZE")
                .unwrap_or_else(|_| "1024".to_string())
                .parse()
                .context("Invalid PERF_BUFFER_SIZE")?,
        })
    }
    
    pub fn validate(&self) -> Result<()> {
        if self.signature_window_size == 0 {
            anyhow::bail!("SIGNATURE_WINDOW_SIZE must be greater than 0");
        }
        if self.signature_window_size > 1024 {
            anyhow::bail!("SIGNATURE_WINDOW_SIZE must be <= 1024");
        }
        if self.max_flows == 0 {
            anyhow::bail!("MAX_FLOWS must be greater than 0");
        }
        if self.perf_buffer_size == 0 || !self.perf_buffer_size.is_power_of_two() {
            anyhow::bail!("PERF_BUFFER_SIZE must be a power of 2");
        }
        Ok(())
    }
}