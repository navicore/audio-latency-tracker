use anyhow::Result;
use axum::{
    routing::get,
    Router,
    response::IntoResponse,
};
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_counter,
    HistogramVec, IntCounterVec, IntCounter, TextEncoder, Encoder,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static::lazy_static! {
    static ref AUDIO_LATENCY: HistogramVec = register_histogram_vec!(
        "audio_latency_seconds",
        "Audio latency between components",
        &["source_pod", "dest_pod", "source_ip", "dest_ip"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).unwrap();
    
    static ref AUDIO_SIGNATURES: IntCounterVec = register_int_counter_vec!(
        "audio_signatures_total",
        "Total audio signatures detected",
        &["pod", "ip", "port"]
    ).unwrap();
    
    static ref SIGNATURE_COLLISIONS: IntCounter = register_int_counter!(
        "audio_signature_collisions_total",
        "Signature hash collisions detected"
    ).unwrap();
    
    static ref PROCESSING_ERRORS: IntCounterVec = register_int_counter_vec!(
        "audio_processing_errors_total",
        "Errors during audio processing",
        &["error_type"]
    ).unwrap();
}

#[derive(Clone)]
pub struct MetricsCollector {
    pod_cache: Arc<RwLock<PodCache>>,
}

#[derive(Default)]
struct PodCache {
    ip_to_pod: std::collections::HashMap<String, String>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            pod_cache: Arc::new(RwLock::new(PodCache::default())),
        }
    }
    
    pub async fn record_latency(
        &self,
        source_ip: &str,
        source_port: u16,
        dest_ip: &str,
        dest_port: u16,
        latency_seconds: f64,
    ) {
        let cache = self.pod_cache.read().await;
        
        let source_pod = cache.ip_to_pod.get(source_ip)
            .cloned()
            .unwrap_or_else(|| format!("unknown-{}", source_ip));
        let dest_pod = cache.ip_to_pod.get(dest_ip)
            .cloned()
            .unwrap_or_else(|| format!("unknown-{}", dest_ip));
        
        AUDIO_LATENCY
            .with_label_values(&[&source_pod, &dest_pod, source_ip, dest_ip])
            .observe(latency_seconds);
    }
    
    pub fn record_signature(&self, ip: &str, port: u16) {
        // For now, use IP as pod identifier
        let pod = format!("{}:{}", ip, port);
        
        AUDIO_SIGNATURES
            .with_label_values(&[&pod, ip, &port.to_string()])
            .inc();
    }
    
    pub fn record_collision(&self) {
        SIGNATURE_COLLISIONS.inc();
    }
    
    pub fn record_error(&self, error_type: &str) {
        PROCESSING_ERRORS
            .with_label_values(&[error_type])
            .inc();
    }
    
    pub async fn update_pod_mapping(&self, ip: String, pod_name: String) {
        let mut cache = self.pod_cache.write().await;
        cache.ip_to_pod.insert(ip, pod_name);
    }
    
    pub async fn start_server(self, port: u16) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler));
        
        log::info!("Starting metrics server on {}", addr);
        
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    (
        [("content-type", "text/plain; version=0.0.4")],
        buffer,
    )
}

async fn health_handler() -> impl IntoResponse {
    "OK"
}