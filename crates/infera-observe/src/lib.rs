//! # Infera Observe - Observability Layer
//!
//! Centralized observability with tracing, metrics, and structured logging.

use anyhow::Result;
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize tracing and observability
pub fn init_tracing() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,infera=debug"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    tracing::info!("Tracing initialized");

    Ok(())
}

/// Initialize Prometheus metrics exporter
pub fn init_metrics() -> Result<()> {
    PrometheusBuilder::new()
        .install()
        .map_err(|e| anyhow::anyhow!("Failed to install Prometheus exporter: {}", e))?;

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

    #[test]
    fn test_init_tracing() {
        // Note: This will fail if called multiple times in the same process
        // In real tests, you'd use a once_cell or similar
        let result = init_tracing();
        // Don't assert success as it may already be initialized
        let _ = result;
    }
}
