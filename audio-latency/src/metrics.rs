use anyhow::Result;
use axum::{response::IntoResponse, routing::get, Router};
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, Encoder, HistogramVec,
    IntCounter, IntCounterVec, TextEncoder,
};
use std::net::SocketAddr;

lazy_static::lazy_static! {
    static ref AUDIO_LATENCY: HistogramVec = register_histogram_vec!(
        "audio_latency_seconds",
        "Audio latency between components",
        &["source_ip", "dest_ip"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).unwrap();

    static ref AUDIO_SIGNATURES: IntCounterVec = register_int_counter_vec!(
        "audio_signatures_total",
        "Total audio signatures detected",
        &["ip", "port"]
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
pub struct MetricsCollector {}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {}
    }

    /// Records latency between two endpoints in Prometheus metrics.
    /// Currently not used because we're logging all events as JSON for external analysis.
    /// This method is preserved for future use when we want to expose aggregate latency
    /// metrics in Prometheus for real-time dashboards (without signature cardinality).
    #[allow(dead_code)]
    pub async fn record_latency(
        &self,
        source_ip: &str,
        _source_port: u16,
        dest_ip: &str,
        _dest_port: u16,
        latency_seconds: f64,
    ) {
        AUDIO_LATENCY
            .with_label_values(&[source_ip, dest_ip])
            .observe(latency_seconds);
    }

    pub fn record_signature(&self, ip: &str, port: u16) {
        AUDIO_SIGNATURES
            .with_label_values(&[ip, &port.to_string()])
            .inc();
    }

    /// Records when we detect a signature hash collision.
    /// Not currently used as we're logging all events and collision detection
    /// will happen during post-processing. Preserved for future real-time
    /// collision detection when we implement more sophisticated correlation.
    #[allow(dead_code)]
    pub fn record_collision(&self) {
        SIGNATURE_COLLISIONS.inc();
    }

    /// Records processing errors by type for monitoring system health.
    /// Currently not used as we're in early stages, but will be important
    /// for production monitoring to track issues like:
    /// - Packet parsing errors
    /// - Container lookup failures
    /// - eBPF map overflow
    #[allow(dead_code)]
    pub fn record_error(&self, error_type: &str) {
        PROCESSING_ERRORS.with_label_values(&[error_type]).inc();
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

    ([("content-type", "text/plain; version=0.0.4")], buffer)
}

async fn health_handler() -> impl IntoResponse {
    "OK"
}
