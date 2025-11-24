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

    // Tailscale-specific metrics
    describe_counter!(
        "inferadb_tailscale_dns_resolutions_total",
        "Total Tailscale MagicDNS resolution attempts with result status"
    );

    describe_gauge!(
        "inferadb_tailscale_discovered_endpoints",
        "Number of endpoints discovered via Tailscale per cluster"
    );

    describe_counter!(
        "inferadb_tailscale_cluster_discovery_failures_total",
        "Total failures when discovering a specific Tailscale cluster"
    );

    describe_gauge!(
        "inferadb_tailscale_clusters_total",
        "Total number of configured Tailscale clusters"
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

/// Record a Tailscale DNS resolution attempt
pub fn record_tailscale_dns_resolution(hostname: &str, result: &str) {
    counter!(
        "inferadb_tailscale_dns_resolutions_total",
        "hostname" => hostname.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

/// Set the number of discovered Tailscale endpoints for a cluster
pub fn set_tailscale_discovered_endpoints(cluster: &str, count: i64) {
    gauge!(
        "inferadb_tailscale_discovered_endpoints",
        "cluster" => cluster.to_string()
    )
    .set(count as f64);
}

/// Record a Tailscale cluster discovery failure
pub fn record_tailscale_cluster_failure(cluster: &str, reason: &str) {
    counter!(
        "inferadb_tailscale_cluster_discovery_failures_total",
        "cluster" => cluster.to_string(),
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Set the total number of configured Tailscale clusters
pub fn set_tailscale_clusters_total(count: i64) {
    gauge!("inferadb_tailscale_clusters_total").set(count as f64);
}
