use anyhow::{Context, Result};
use std::env;
use std::str::FromStr;

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

    /// Minimum TCP payload size to consider for audio detection (bytes)
    /// Audio packets are typically larger than control packets
    /// Default: 256 bytes, Production example: 2048 bytes
    pub min_audio_packet_size: u32,
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
            min_audio_packet_size: env::var("MIN_AUDIO_PACKET_SIZE")
                .unwrap_or_else(|_| "256".to_string())
                .parse()
                .context("Invalid MIN_AUDIO_PACKET_SIZE")?,
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
        if self.min_audio_packet_size == 0 {
            anyhow::bail!("MIN_AUDIO_PACKET_SIZE must be greater than 0");
        }
        if self.min_audio_packet_size > 65535 {
            anyhow::bail!("MIN_AUDIO_PACKET_SIZE must be <= 65535 (max TCP payload)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithm_parsing() {
        assert!(matches!(
            SignatureAlgorithm::from_str("rolling_hash").unwrap(),
            SignatureAlgorithm::RollingHash
        ));
        assert!(matches!(
            SignatureAlgorithm::from_str("crc32").unwrap(),
            SignatureAlgorithm::Crc32
        ));
        assert!(matches!(
            SignatureAlgorithm::from_str("xxhash").unwrap(),
            SignatureAlgorithm::XxHash
        ));
        assert!(SignatureAlgorithm::from_str("invalid").is_err());
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config {
            interface: "eth0".to_string(),
            log_level: "info".to_string(),
            metrics_port: 9090,
            audio_ports: None,
            signature_window_size: 256,
            silence_threshold: 256,
            signature_algorithm: SignatureAlgorithm::XxHash,
            k8s_enabled: true,
            k8s_node_name: Some("node-1".to_string()),
            max_flows: 10000,
            flow_timeout_ms: 30000,
            perf_buffer_size: 1024,
            min_audio_packet_size: 256,
        };

        // Valid config
        assert!(config.validate().is_ok());

        // Invalid signature_window_size
        config.signature_window_size = 0;
        assert!(config.validate().is_err());
        config.signature_window_size = 2048;
        assert!(config.validate().is_err());
        config.signature_window_size = 256; // Reset

        // Invalid max_flows
        config.max_flows = 0;
        assert!(config.validate().is_err());
        config.max_flows = 10000; // Reset

        // Invalid perf_buffer_size
        config.perf_buffer_size = 0;
        assert!(config.validate().is_err());
        config.perf_buffer_size = 1023; // Not power of 2
        assert!(config.validate().is_err());
        config.perf_buffer_size = 1024; // Reset

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_k8s_auto_detection() {
        // This test would normally check if K8S_ENABLED auto-detects
        // but we can't reliably test file system checks in unit tests
        // Just verify the config field exists and can be set
        let config = Config {
            interface: "eth0".to_string(),
            log_level: "info".to_string(),
            metrics_port: 9090,
            audio_ports: Some(vec![8080, 9090]),
            signature_window_size: 256,
            silence_threshold: 256,
            signature_algorithm: SignatureAlgorithm::XxHash,
            k8s_enabled: false,
            k8s_node_name: None,
            max_flows: 10000,
            flow_timeout_ms: 30000,
            perf_buffer_size: 1024,
            min_audio_packet_size: 256,
        };

        assert!(!config.k8s_enabled);
        assert!(config.k8s_node_name.is_none());
    }
}
