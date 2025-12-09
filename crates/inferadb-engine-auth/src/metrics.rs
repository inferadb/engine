use inferadb_engine_control_client::vault_verifier::VaultVerifierMetrics;
use prometheus::{
    HistogramVec, IntCounterVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry,
};

/// Authentication metrics for monitoring
#[derive(Clone)]
pub struct AuthMetrics {
    /// Counter for total authentication validations
    pub auth_validations_total: IntCounterVec,

    /// Counter for cache hits
    pub cache_hits_total: IntCounterVec,

    /// Counter for cache misses
    pub cache_misses_total: IntCounterVec,

    /// Counter for Control API calls
    pub control_api_calls_total: IntCounterVec,

    /// Histogram for authentication validation duration
    pub auth_validation_duration_seconds: HistogramVec,
}

impl AuthMetrics {
    /// Create a new AuthMetrics instance and register all metrics with the given registry
    ///
    /// # Arguments
    ///
    /// * `registry` - Prometheus registry to register metrics with
    ///
    /// # Errors
    ///
    /// Returns an error if any metric fails to register with the registry
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let auth_validations_total = register_int_counter_vec_with_registry!(
            "inferadb_auth_validations_total",
            "Total number of authentication validations",
            &["method", "result"],
            registry
        )?;

        let cache_hits_total = register_int_counter_vec_with_registry!(
            "inferadb_auth_cache_hits_total",
            "Total number of authentication cache hits",
            &["cache_type"],
            registry
        )?;

        let cache_misses_total = register_int_counter_vec_with_registry!(
            "inferadb_auth_cache_misses_total",
            "Total number of authentication cache misses",
            &["cache_type"],
            registry
        )?;

        let control_api_calls_total = register_int_counter_vec_with_registry!(
            "inferadb_auth_control_api_calls_total",
            "Total number of calls to Control",
            &["endpoint", "status"],
            registry
        )?;

        let auth_validation_duration_seconds = register_histogram_vec_with_registry!(
            "inferadb_auth_validation_duration_seconds",
            "Duration of authentication validation in seconds",
            &["method"],
            registry
        )?;

        Ok(Self {
            auth_validations_total,
            cache_hits_total,
            cache_misses_total,
            control_api_calls_total,
            auth_validation_duration_seconds,
        })
    }

    /// Record a successful authentication validation
    pub fn record_validation_success(&self, method: &str) {
        self.auth_validations_total.with_label_values(&[method, "success"]).inc();
    }

    /// Record a failed authentication validation
    pub fn record_validation_failure(&self, method: &str) {
        self.auth_validations_total.with_label_values(&[method, "failure"]).inc();
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self, cache_type: &str) {
        self.cache_hits_total.with_label_values(&[cache_type]).inc();
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self, cache_type: &str) {
        self.cache_misses_total.with_label_values(&[cache_type]).inc();
    }

    /// Record a Control API call
    pub fn record_control_api_call(&self, endpoint: &str, status: u16) {
        self.control_api_calls_total.with_label_values(&[endpoint, &status.to_string()]).inc();
    }

    /// Start timing an authentication validation
    pub fn start_validation_timer(&self, method: &str) -> prometheus::HistogramTimer {
        self.auth_validation_duration_seconds.with_label_values(&[method]).start_timer()
    }

    /// Record a cache invalidation event
    pub fn record_cache_invalidation(&self, cache_type: &str, reason: &str) {
        // Use cache_misses_total with a special label pattern for invalidations
        // This allows monitoring invalidation rates without adding a new metric
        self.cache_misses_total
            .with_label_values(&[&format!("{}_invalidation_{}", cache_type, reason)])
            .inc();
    }
}

impl VaultVerifierMetrics for AuthMetrics {
    fn record_cache_hit(&self, cache_type: &str) {
        AuthMetrics::record_cache_hit(self, cache_type);
    }

    fn record_cache_miss(&self, cache_type: &str) {
        AuthMetrics::record_cache_miss(self, cache_type);
    }

    fn record_cache_invalidation(&self, cache_type: &str, reason: &str) {
        AuthMetrics::record_cache_invalidation(self, cache_type, reason);
    }

    fn record_control_api_call(&self, operation: &str, status: u16) {
        AuthMetrics::record_control_api_call(self, operation, status);
    }
}
