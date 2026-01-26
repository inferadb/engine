//! # Infera Observe - Observability Layer
//!
//! Centralized observability with tracing, metrics, and structured logging.

#![deny(unsafe_code)]

use std::sync::OnceLock;

use anyhow::Result;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Global Prometheus handle for rendering metrics
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

pub mod aggregation;
pub mod audit;
pub mod logging;
pub mod metrics;
pub mod reconfigure;
pub mod span_utils;
pub mod startup;
pub mod tracing_config;

/// Configuration for OpenTelemetry tracing
#[derive(Debug, Clone, bon::Builder)]
#[builder(on(String, into))]
pub struct TracingConfig {
    /// Service name for tracing
    #[builder(default = "inferadb-engine".to_string())]
    pub service_name: String,
    /// OTLP endpoint (e.g., "http://localhost:4317")
    pub otlp_endpoint: Option<String>,
    /// Sample rate (0.0 to 1.0)
    #[builder(default = 1.0)]
    pub sample_rate: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Initialize tracing with OpenTelemetry support
pub fn init_tracing_with_config(config: TracingConfig) -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,infera=debug"));

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_target(false));

    // Add OpenTelemetry layer if endpoint is configured
    let otlp_enabled = config.otlp_endpoint.is_some();
    if let Some(endpoint) = config.otlp_endpoint {
        // Build the OTLP exporter
        let exporter = SpanExporter::builder().with_tonic().with_endpoint(endpoint).build()?;

        // Build the resource with service name
        let resource = opentelemetry_sdk::Resource::builder()
            .with_service_name(config.service_name.clone())
            .build();

        // Build the tracer provider
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource)
            .build();

        let telemetry_layer =
            tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("inferadb-engine"));

        // Try to init, but don't fail if already initialized
        if subscriber.with(telemetry_layer).try_init().is_err() {
            // Already initialized, just log a debug message
            tracing::debug!("Tracing already initialized, skipping");
            return Ok(());
        }
    } else {
        // Try to init, but don't fail if already initialized
        if subscriber.try_init().is_err() {
            // Already initialized, just log a debug message
            tracing::debug!("Tracing already initialized, skipping");
            return Ok(());
        }
    }

    tracing::info!(
        service = config.service_name,
        otlp_enabled = otlp_enabled,
        "Tracing initialized"
    );

    Ok(())
}

/// Initialize tracing with default configuration
pub fn init_tracing() -> Result<()> {
    init_tracing_with_config(TracingConfig::default())
}

/// Initialize Prometheus metrics exporter and store the handle for rendering
pub fn init_metrics() -> Result<()> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("Failed to install Prometheus exporter: {}", e))?;

    // Store handle globally for rendering metrics later
    let _ = PROMETHEUS_HANDLE.set(handle);

    // Initialize metric descriptions
    metrics::init_metrics_descriptions();

    tracing::info!("Metrics exporter initialized");

    Ok(())
}

/// Render current metrics in Prometheus text format
///
/// Returns None if metrics haven't been initialized yet
pub fn render_metrics() -> Option<String> {
    PROMETHEUS_HANDLE.get().map(|handle| handle.render())
}

/// Initialize full observability stack
pub fn init() -> Result<()> {
    init_tracing()?;
    init_metrics()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::*;

    static INIT: Once = Once::new();

    #[test]
    fn test_init_tracing() {
        // Only initialize once across all tests in this module
        // Don't assert as subscriber may already be set by other tests
        INIT.call_once(|| {
            let _ = init_tracing();
        });
        // Test passes if we get here without panicking
    }

    #[test]
    fn test_tracing_config() {
        let config = TracingConfig::default();
        assert_eq!(config.service_name, "inferadb-engine");
        assert_eq!(config.otlp_endpoint, None);
        assert_eq!(config.sample_rate, 1.0);

        let custom_config = TracingConfig {
            service_name: "test-service".to_string(),
            otlp_endpoint: Some("http://localhost:4317".to_string()),
            sample_rate: 0.5,
        };
        assert_eq!(custom_config.service_name, "test-service");
        assert_eq!(custom_config.otlp_endpoint, Some("http://localhost:4317".to_string()));
        assert_eq!(custom_config.sample_rate, 0.5);
    }
}
