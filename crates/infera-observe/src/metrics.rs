//! Metrics collection for InferaDB operations
//!
//! Provides structured metrics using the `metrics` crate with Prometheus export.

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};

/// Initialize all metric descriptions
pub fn init_metrics_descriptions() {
    // Authorization check metrics
    describe_counter!(
        "inferadb_checks_total",
        "Total number of authorization checks performed"
    );
    describe_counter!(
        "inferadb_checks_allowed_total",
        "Total number of checks that resulted in Allow"
    );
    describe_counter!(
        "inferadb_checks_denied_total",
        "Total number of checks that resulted in Deny"
    );
    describe_histogram!(
        "inferadb_check_duration_seconds",
        "Duration of authorization checks in seconds"
    );

    // Cache metrics
    describe_counter!("inferadb_cache_hits_total", "Total number of cache hits");
    describe_counter!(
        "inferadb_cache_misses_total",
        "Total number of cache misses"
    );
    describe_gauge!(
        "inferadb_cache_entries",
        "Current number of entries in the cache"
    );
    describe_gauge!(
        "inferadb_cache_hit_rate",
        "Current cache hit rate as a percentage"
    );

    // Storage metrics
    describe_counter!(
        "inferadb_storage_reads_total",
        "Total number of storage read operations"
    );
    describe_counter!(
        "inferadb_storage_writes_total",
        "Total number of storage write operations"
    );
    describe_histogram!(
        "inferadb_storage_read_duration_seconds",
        "Duration of storage read operations in seconds"
    );
    describe_histogram!(
        "inferadb_storage_write_duration_seconds",
        "Duration of storage write operations in seconds"
    );
    describe_gauge!(
        "inferadb_storage_tuples_total",
        "Total number of tuples in storage"
    );
    describe_gauge!(
        "inferadb_storage_revision",
        "Current storage revision number"
    );

    // WASM metrics
    describe_counter!(
        "inferadb_wasm_invocations_total",
        "Total number of WASM module invocations"
    );
    describe_counter!(
        "inferadb_wasm_errors_total",
        "Total number of WASM execution errors"
    );
    describe_histogram!(
        "inferadb_wasm_duration_seconds",
        "Duration of WASM module executions in seconds"
    );
    describe_histogram!(
        "inferadb_wasm_fuel_consumed",
        "Amount of fuel consumed by WASM executions"
    );

    // Evaluation metrics
    describe_counter!(
        "inferadb_evaluations_total",
        "Total number of relation evaluations"
    );
    describe_histogram!(
        "inferadb_evaluation_depth",
        "Depth of relation evaluation trees"
    );
    describe_histogram!(
        "inferadb_evaluation_branches",
        "Number of branches evaluated per check"
    );

    // Query optimization metrics
    describe_counter!(
        "inferadb_optimizations_total",
        "Total number of query optimizations performed"
    );
    describe_histogram!("inferadb_query_cost_estimated", "Estimated cost of queries");
    describe_counter!(
        "inferadb_parallel_evaluations_total",
        "Total number of parallel evaluations"
    );

    // API metrics
    describe_counter!(
        "inferadb_api_requests_total",
        "Total number of API requests by endpoint and method"
    );
    describe_counter!(
        "inferadb_api_errors_total",
        "Total number of API errors by endpoint and status code"
    );
    describe_histogram!(
        "inferadb_api_request_duration_seconds",
        "Duration of API requests in seconds"
    );
    describe_gauge!(
        "inferadb_api_active_connections",
        "Number of currently active API connections"
    );

    // Authentication metrics
    describe_counter!(
        "inferadb_auth_attempts_total",
        "Total number of authentication attempts"
    );
    describe_counter!(
        "inferadb_auth_success_total",
        "Total number of successful authentications"
    );
    describe_counter!(
        "inferadb_auth_failure_total",
        "Total number of failed authentications"
    );
    describe_histogram!(
        "inferadb_auth_duration_seconds",
        "Duration of authentication operations in seconds"
    );
    describe_counter!(
        "inferadb_jwt_signature_verifications_total",
        "Total number of JWT signature verifications"
    );
    describe_counter!(
        "inferadb_jwt_validation_errors_total",
        "Total number of JWT validation errors"
    );

    // JWKS metrics
    describe_counter!(
        "inferadb_jwks_cache_hits_total",
        "Total number of JWKS cache hits"
    );
    describe_counter!(
        "inferadb_jwks_cache_misses_total",
        "Total number of JWKS cache misses"
    );
    describe_counter!(
        "inferadb_jwks_refresh_total",
        "Total number of JWKS refresh operations"
    );
    describe_counter!(
        "inferadb_jwks_refresh_errors_total",
        "Total number of JWKS refresh errors"
    );
    describe_histogram!(
        "inferadb_jwks_fetch_duration_seconds",
        "Duration of JWKS fetch operations in seconds"
    );
    describe_counter!(
        "inferadb_jwks_stale_served_total",
        "Total number of times stale JWKS was served"
    );

    // OAuth metrics
    describe_counter!(
        "inferadb_oauth_jwt_validations_total",
        "Total number of OAuth JWT validation attempts"
    );
    describe_counter!(
        "inferadb_oauth_introspections_total",
        "Total number of OAuth token introspection attempts"
    );
    describe_counter!(
        "inferadb_oauth_introspection_cache_hits_total",
        "Total number of OAuth introspection cache hits"
    );
    describe_counter!(
        "inferadb_oauth_introspection_cache_misses_total",
        "Total number of OAuth introspection cache misses"
    );
    describe_counter!(
        "inferadb_oidc_discovery_total",
        "Total number of OIDC discovery attempts"
    );
    describe_histogram!(
        "inferadb_oauth_introspection_duration_seconds",
        "Duration of OAuth token introspection in seconds"
    );

    // Replication metrics
    describe_counter!(
        "inferadb_replication_changes_total",
        "Total number of changes replicated to remote regions"
    );
    describe_counter!(
        "inferadb_replication_failures_total",
        "Total number of replication failures"
    );
    describe_counter!(
        "inferadb_replication_conflicts_total",
        "Total number of replication conflicts detected"
    );
    describe_counter!(
        "inferadb_replication_conflicts_resolved_local",
        "Number of conflicts resolved by keeping local change"
    );
    describe_counter!(
        "inferadb_replication_conflicts_resolved_remote",
        "Number of conflicts resolved by keeping remote change"
    );
    describe_gauge!(
        "inferadb_replication_lag_milliseconds",
        "Current replication lag in milliseconds"
    );
    describe_gauge!(
        "inferadb_replication_targets_connected",
        "Number of replication targets currently connected"
    );
    describe_gauge!(
        "inferadb_replication_targets_total",
        "Total number of configured replication targets"
    );
    describe_histogram!(
        "inferadb_replication_batch_size",
        "Size of replication batches"
    );
    describe_histogram!(
        "inferadb_replication_duration_seconds",
        "Duration of replication operations in seconds"
    );

    // System metrics
    describe_gauge!(
        "inferadb_build_info",
        "Build information (version, commit, etc.)"
    );
    describe_gauge!(
        "inferadb_uptime_seconds",
        "Time since server started in seconds"
    );
}

/// Record an authorization check
pub fn record_check(decision: &str, duration_seconds: f64) {
    counter!("inferadb_checks_total").increment(1);

    match decision {
        "allow" => counter!("inferadb_checks_allowed_total").increment(1),
        "deny" => counter!("inferadb_checks_denied_total").increment(1),
        _ => {}
    }

    histogram!("inferadb_check_duration_seconds").record(duration_seconds);
}

/// Record a cache operation
pub fn record_cache_hit(hit: bool) {
    if hit {
        counter!("inferadb_cache_hits_total").increment(1);
    } else {
        counter!("inferadb_cache_misses_total").increment(1);
    }
}

/// Update cache statistics
pub fn update_cache_stats(entries: usize, hit_rate: f64) {
    gauge!("inferadb_cache_entries").set(entries as f64);
    gauge!("inferadb_cache_hit_rate").set(hit_rate);
}

/// Record a storage read operation
pub fn record_storage_read(duration_seconds: f64, tuples_read: usize) {
    counter!("inferadb_storage_reads_total").increment(1);
    histogram!("inferadb_storage_read_duration_seconds").record(duration_seconds);

    // Optionally record tuples read as a histogram
    histogram!("inferadb_storage_tuples_read").record(tuples_read as f64);
}

/// Record a storage write operation
pub fn record_storage_write(duration_seconds: f64, tuples_written: usize) {
    counter!("inferadb_storage_writes_total").increment(1);
    histogram!("inferadb_storage_write_duration_seconds").record(duration_seconds);
    histogram!("inferadb_storage_tuples_written").record(tuples_written as f64);
}

/// Update storage statistics
pub fn update_storage_stats(total_tuples: usize, revision: u64) {
    gauge!("inferadb_storage_tuples_total").set(total_tuples as f64);
    gauge!("inferadb_storage_revision").set(revision as f64);
}

/// Record a WASM invocation
pub fn record_wasm_invocation(
    module: &str,
    duration_seconds: f64,
    fuel_consumed: u64,
    success: bool,
) {
    counter!("inferadb_wasm_invocations_total", "module" => module.to_string()).increment(1);

    if !success {
        counter!("inferadb_wasm_errors_total", "module" => module.to_string()).increment(1);
    }

    histogram!("inferadb_wasm_duration_seconds", "module" => module.to_string())
        .record(duration_seconds);
    histogram!("inferadb_wasm_fuel_consumed", "module" => module.to_string())
        .record(fuel_consumed as f64);
}

/// Record a relation evaluation
pub fn record_evaluation(depth: usize, branches: usize) {
    counter!("inferadb_evaluations_total").increment(1);
    histogram!("inferadb_evaluation_depth").record(depth as f64);
    histogram!("inferadb_evaluation_branches").record(branches as f64);
}

/// Record a query optimization
pub fn record_optimization(estimated_cost: usize, parallelizable: bool) {
    counter!("inferadb_optimizations_total").increment(1);
    histogram!("inferadb_query_cost_estimated").record(estimated_cost as f64);

    if parallelizable {
        counter!("inferadb_parallel_evaluations_total").increment(1);
    }
}

/// Record an API request
pub fn record_api_request(endpoint: &str, method: &str, status_code: u16, duration_seconds: f64) {
    counter!(
        "inferadb_api_requests_total",
        "endpoint" => endpoint.to_string(),
        "method" => method.to_string(),
        "status" => status_code.to_string()
    )
    .increment(1);

    if status_code >= 400 {
        counter!(
            "inferadb_api_errors_total",
            "endpoint" => endpoint.to_string(),
            "status" => status_code.to_string()
        )
        .increment(1);
    }

    histogram!(
        "inferadb_api_request_duration_seconds",
        "endpoint" => endpoint.to_string(),
        "method" => method.to_string()
    )
    .record(duration_seconds);
}

/// Update active connections count
pub fn update_active_connections(count: i64) {
    gauge!("inferadb_api_active_connections").increment(count as f64);
}

/// Set build information
pub fn set_build_info(version: &str, commit: &str) {
    gauge!(
        "inferadb_build_info",
        "version" => version.to_string(),
        "commit" => commit.to_string()
    )
    .set(1.0);
}

/// Update uptime metric
pub fn update_uptime(seconds: u64) {
    gauge!("inferadb_uptime_seconds").set(seconds as f64);
}

/// Record an authentication attempt
pub fn record_auth_attempt(method: &str, tenant_id: &str) {
    counter!(
        "inferadb_auth_attempts_total",
        "method" => method.to_string(),
        "tenant_id" => tenant_id.to_string()
    )
    .increment(1);
}

/// Record a successful authentication
pub fn record_auth_success(method: &str, tenant_id: &str, duration_seconds: f64) {
    counter!(
        "inferadb_auth_success_total",
        "method" => method.to_string(),
        "tenant_id" => tenant_id.to_string()
    )
    .increment(1);

    histogram!(
        "inferadb_auth_duration_seconds",
        "method" => method.to_string(),
        "tenant_id" => tenant_id.to_string()
    )
    .record(duration_seconds);
}

/// Record a failed authentication
pub fn record_auth_failure(method: &str, error_type: &str, tenant_id: &str, duration_seconds: f64) {
    counter!(
        "inferadb_auth_failure_total",
        "method" => method.to_string(),
        "error_type" => error_type.to_string(),
        "tenant_id" => tenant_id.to_string()
    )
    .increment(1);

    histogram!(
        "inferadb_auth_duration_seconds",
        "method" => method.to_string(),
        "tenant_id" => tenant_id.to_string()
    )
    .record(duration_seconds);
}

/// Record a JWT signature verification
pub fn record_jwt_signature_verification(algorithm: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    counter!(
        "inferadb_jwt_signature_verifications_total",
        "algorithm" => algorithm.to_string(),
        "result" => result
    )
    .increment(1);
}

/// Record a JWT validation error
pub fn record_jwt_validation_error(error_type: &str) {
    counter!(
        "inferadb_jwt_validation_errors_total",
        "error_type" => error_type.to_string()
    )
    .increment(1);
}

/// Record a JWKS cache hit
pub fn record_jwks_cache_hit(tenant_id: &str) {
    counter!("inferadb_jwks_cache_hits_total", "tenant_id" => tenant_id.to_string()).increment(1);
}

/// Record a JWKS cache miss
pub fn record_jwks_cache_miss(tenant_id: &str) {
    counter!("inferadb_jwks_cache_misses_total", "tenant_id" => tenant_id.to_string()).increment(1);
}

/// Record a JWKS refresh operation
pub fn record_jwks_refresh(tenant_id: &str, duration_seconds: f64, success: bool) {
    counter!("inferadb_jwks_refresh_total", "tenant_id" => tenant_id.to_string()).increment(1);

    if !success {
        counter!("inferadb_jwks_refresh_errors_total", "tenant_id" => tenant_id.to_string())
            .increment(1);
    }

    histogram!("inferadb_jwks_fetch_duration_seconds", "tenant_id" => tenant_id.to_string())
        .record(duration_seconds);
}

/// Record when stale JWKS is served (stale-while-revalidate)
pub fn record_jwks_stale_served(tenant_id: &str) {
    counter!("inferadb_jwks_stale_served_total", "tenant_id" => tenant_id.to_string()).increment(1);
}

/// Record an OAuth JWT validation attempt
pub fn record_oauth_jwt_validation(issuer: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    counter!(
        "inferadb_oauth_jwt_validations_total",
        "issuer" => issuer.to_string(),
        "result" => result
    )
    .increment(1);
}

/// Record an OAuth token introspection attempt
pub fn record_oauth_introspection(success: bool, duration_seconds: f64) {
    let result = if success { "success" } else { "failure" };
    counter!(
        "inferadb_oauth_introspections_total",
        "result" => result
    )
    .increment(1);

    histogram!("inferadb_oauth_introspection_duration_seconds").record(duration_seconds);
}

/// Record an OAuth introspection cache hit
pub fn record_oauth_introspection_cache_hit() {
    counter!("inferadb_oauth_introspection_cache_hits_total").increment(1);
}

/// Record an OAuth introspection cache miss
pub fn record_oauth_introspection_cache_miss() {
    counter!("inferadb_oauth_introspection_cache_misses_total").increment(1);
}

/// Record an OIDC discovery attempt
pub fn record_oidc_discovery(issuer: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    counter!(
        "inferadb_oidc_discovery_total",
        "issuer" => issuer.to_string(),
        "result" => result
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_metrics() {
        INIT.call_once(|| {
            let _ = metrics_exporter_prometheus::PrometheusBuilder::new().install();
            init_metrics_descriptions();
        });
    }

    #[test]
    fn test_record_check() {
        init_test_metrics();
        record_check("allow", 0.001);
        record_check("deny", 0.002);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_cache_operations() {
        init_test_metrics();
        record_cache_hit(true);
        record_cache_hit(false);
        update_cache_stats(100, 75.5);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_storage_operations() {
        init_test_metrics();
        record_storage_read(0.001, 10);
        record_storage_write(0.002, 5);
        update_storage_stats(1000, 42);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_wasm_invocation() {
        init_test_metrics();
        record_wasm_invocation("test_module", 0.005, 1000, true);
        record_wasm_invocation("test_module", 0.010, 2000, false);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_evaluation() {
        init_test_metrics();
        record_evaluation(5, 3);
        record_evaluation(10, 7);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_optimization() {
        init_test_metrics();
        record_optimization(15, true);
        record_optimization(5, false);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_api_request() {
        init_test_metrics();
        record_api_request("/check", "POST", 200, 0.001);
        record_api_request("/check", "POST", 500, 0.010);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_update_active_connections() {
        init_test_metrics();
        update_active_connections(1);
        update_active_connections(-1);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_set_build_info() {
        init_test_metrics();
        set_build_info("0.1.0", "abc123");
        // Just verify it doesn't panic
    }

    #[test]
    fn test_update_uptime() {
        init_test_metrics();
        update_uptime(3600);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_init_metrics_descriptions() {
        init_test_metrics();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_jwks_cache_hit() {
        init_test_metrics();
        record_jwks_cache_hit("test-tenant");
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_jwks_cache_miss() {
        init_test_metrics();
        record_jwks_cache_miss("test-tenant");
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_jwks_refresh_success() {
        init_test_metrics();
        record_jwks_refresh("test-tenant", 0.5, true);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_jwks_refresh_failure() {
        init_test_metrics();
        record_jwks_refresh("test-tenant", 1.2, false);
        // Just verify it doesn't panic and records error counter
    }

    #[test]
    fn test_record_oauth_jwt_validation_success() {
        init_test_metrics();
        record_oauth_jwt_validation("https://oauth.example.com", true);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_oauth_jwt_validation_failure() {
        init_test_metrics();
        record_oauth_jwt_validation("https://oauth.example.com", false);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_oauth_introspection_success() {
        init_test_metrics();
        record_oauth_introspection(true, 0.05);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_oauth_introspection_failure() {
        init_test_metrics();
        record_oauth_introspection(false, 0.1);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_oauth_introspection_cache_hit() {
        init_test_metrics();
        record_oauth_introspection_cache_hit();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_oauth_introspection_cache_miss() {
        init_test_metrics();
        record_oauth_introspection_cache_miss();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_oidc_discovery_success() {
        init_test_metrics();
        record_oidc_discovery("https://oauth.example.com", true);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_oidc_discovery_failure() {
        init_test_metrics();
        record_oidc_discovery("https://oauth.example.com", false);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_auth_attempt() {
        init_test_metrics();
        record_auth_attempt("tenant_jwt", "test-tenant");
        record_auth_attempt("internal_jwt", "internal");
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_auth_success() {
        init_test_metrics();
        record_auth_success("tenant_jwt", "test-tenant", 0.01);
        record_auth_success("oauth_jwt", "another-tenant", 0.02);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_auth_failure() {
        init_test_metrics();
        record_auth_failure("tenant_jwt", "token_expired", "test-tenant", 0.005);
        record_auth_failure("oauth_jwt", "invalid_signature", "another-tenant", 0.008);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_jwt_signature_verification() {
        init_test_metrics();
        record_jwt_signature_verification("EdDSA", true);
        record_jwt_signature_verification("RS256", false);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_jwt_validation_error() {
        init_test_metrics();
        record_jwt_validation_error("expired");
        record_jwt_validation_error("invalid_signature");
        record_jwt_validation_error("missing_claim");
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_jwks_stale_served() {
        init_test_metrics();
        record_jwks_stale_served("test-tenant");
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_replication_metrics() {
        init_test_metrics();
        record_replication_changes(10, 0.5);
        record_replication_failure(2);
        record_replication_conflict("local");
        record_replication_conflict("remote");
        update_replication_lag(50);
        update_replication_targets(3, 5);
        record_replication_batch(25);
        // Just verify it doesn't panic
    }
}

/// Record replication changes
pub fn record_replication_changes(count: u64, duration_seconds: f64) {
    counter!("inferadb_replication_changes_total").increment(count);
    histogram!("inferadb_replication_duration_seconds").record(duration_seconds);
}

/// Record replication failure
pub fn record_replication_failure(count: u64) {
    counter!("inferadb_replication_failures_total").increment(count);
}

/// Record replication conflict
pub fn record_replication_conflict(resolution: &str) {
    counter!("inferadb_replication_conflicts_total").increment(1);

    match resolution {
        "local" => counter!("inferadb_replication_conflicts_resolved_local").increment(1),
        "remote" => counter!("inferadb_replication_conflicts_resolved_remote").increment(1),
        _ => {}
    }
}

/// Update replication lag
pub fn update_replication_lag(lag_milliseconds: u64) {
    gauge!("inferadb_replication_lag_milliseconds").set(lag_milliseconds as f64);
}

/// Update replication targets
pub fn update_replication_targets(connected: usize, total: usize) {
    gauge!("inferadb_replication_targets_connected").set(connected as f64);
    gauge!("inferadb_replication_targets_total").set(total as f64);
}

/// Record replication batch
pub fn record_replication_batch(batch_size: usize) {
    histogram!("inferadb_replication_batch_size").record(batch_size as f64);
}
