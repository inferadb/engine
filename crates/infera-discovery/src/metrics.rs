//! Metrics for service discovery and load balancing
//!
//! Provides Prometheus metrics for monitoring discovery operations,
//! load balancing behavior, and endpoint health.

use metrics::{counter, describe_counter, describe_gauge, gauge};

/// Initialize metric descriptions for discovery and load balancing
pub fn init_discovery_metrics() {
    // Load balancing request metrics
    describe_counter!(
        "inferadb_lb_requests_total",
        "Total requests per endpoint with result status"
    );

    // Endpoint health gauge
    describe_gauge!(
        "inferadb_lb_endpoint_health",
        "Endpoint health status (1=healthy, 0=unhealthy)"
    );

    // Failover event counter
    describe_counter!(
        "inferadb_lb_failovers_total",
        "Total failover events from one endpoint to another"
    );

    // Discovery operation counter
    describe_counter!(
        "inferadb_discovery_operations_total",
        "Total discovery operations with result status"
    );
}

/// Record a load balancing request
pub fn record_lb_request(endpoint: &str, result: &str) {
    counter!("inferadb_lb_requests_total", "endpoint" => endpoint.to_string(), "result" => result.to_string()).increment(1);
}

/// Update endpoint health status
pub fn set_endpoint_health(endpoint: &str, healthy: bool) {
    let value = if healthy { 1.0 } else { 0.0 };
    gauge!("inferadb_lb_endpoint_health", "endpoint" => endpoint.to_string()).set(value);
}

/// Record a failover event
pub fn record_failover(from: &str, to: &str) {
    counter!("inferadb_lb_failovers_total", "from" => from.to_string(), "to" => to.to_string())
        .increment(1);
}

/// Record a discovery operation
pub fn record_discovery_operation(result: &str) {
    counter!("inferadb_discovery_operations_total", "result" => result.to_string()).increment(1);
}
