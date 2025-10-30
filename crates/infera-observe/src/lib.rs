//! # Infera Observe - Observability Layer
//!
//! Centralized observability with tracing, metrics, and structured logging.

use anyhow::Result;
use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::{trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    trace::{RandomIdGenerator, Sampler},
    Resource,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod logging;
pub mod metrics;
pub mod span_utils;
pub mod tracing_config;

/// Configuration for OpenTelemetry tracing
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Service name for tracing
    pub service_name: String,
    /// OTLP endpoint (e.g., "http://localhost:4317")
    pub otlp_endpoint: Option<String>,
    /// Sample rate (0.0 to 1.0)
    pub sample_rate: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            service_name: "inferadb".to_string(),
            otlp_endpoint: None,
            sample_rate: 1.0,
        }
    }
}

/// Initialize tracing with OpenTelemetry support
pub fn init_tracing_with_config(config: TracingConfig) -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,infera=debug"));

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_target(true));

    // Add OpenTelemetry layer if endpoint is configured
    let otlp_enabled = config.otlp_endpoint.is_some();
    if let Some(endpoint) = config.otlp_endpoint {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(endpoint),
            )
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default()
                    .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
                    .with_id_generator(RandomIdGenerator::default())
                    .with_resource(Resource::new(vec![KeyValue::new(
                        "service.name",
                        config.service_name.clone(),
                    )])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer.tracer("inferadb"));

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

/// Initialize Prometheus metrics exporter
pub fn init_metrics() -> Result<()> {
    PrometheusBuilder::new()
        .install()
        .map_err(|e| anyhow::anyhow!("Failed to install Prometheus exporter: {}", e))?;

    // Initialize metric descriptions
    metrics::init_metrics_descriptions();

    tracing::info!("Metrics exporter initialized");

    Ok(())
}

/// Initialize full observability stack
pub fn init() -> Result<()> {
    init_tracing()?;
    init_metrics()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

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
        assert_eq!(config.service_name, "inferadb");
        assert_eq!(config.otlp_endpoint, None);
        assert_eq!(config.sample_rate, 1.0);

        let custom_config = TracingConfig {
            service_name: "test-service".to_string(),
            otlp_endpoint: Some("http://localhost:4317".to_string()),
            sample_rate: 0.5,
        };
        assert_eq!(custom_config.service_name, "test-service");
        assert_eq!(
            custom_config.otlp_endpoint,
            Some("http://localhost:4317".to_string())
        );
        assert_eq!(custom_config.sample_rate, 0.5);
    }
}
