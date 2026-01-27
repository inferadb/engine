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

    /// Counter for fallback cache usage during Ledger outages
    pub fallback_used_total: IntCounterVec,

    /// Counter for Control API calls
    pub control_api_calls_total: IntCounterVec,

    /// Histogram for authentication validation duration
    pub auth_validation_duration_seconds: HistogramVec,

    /// Histogram for Ledger key lookup duration (fetch from storage)
    pub ledger_key_lookup_duration_seconds: HistogramVec,

    /// Counter for key validation failures by reason
    pub key_validation_failures_total: IntCounterVec,
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

        let fallback_used_total = register_int_counter_vec_with_registry!(
            "inferadb_auth_fallback_used_total",
            "Total number of fallback cache uses during Ledger outages",
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

        let ledger_key_lookup_duration_seconds = register_histogram_vec_with_registry!(
            "inferadb_auth_ledger_key_lookup_duration_seconds",
            "Duration of Ledger key lookup operations in seconds",
            &["result"],
            registry
        )?;

        let key_validation_failures_total = register_int_counter_vec_with_registry!(
            "inferadb_auth_key_validation_failures_total",
            "Total number of key validation failures by reason",
            &["reason"],
            registry
        )?;

        Ok(Self {
            auth_validations_total,
            cache_hits_total,
            cache_misses_total,
            fallback_used_total,
            control_api_calls_total,
            auth_validation_duration_seconds,
            ledger_key_lookup_duration_seconds,
            key_validation_failures_total,
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

    /// Record a fallback cache usage during Ledger outage
    pub fn record_fallback_used(&self, cache_type: &str) {
        self.fallback_used_total.with_label_values(&[cache_type]).inc();
    }

    /// Record a Control API call
    pub fn record_control_api_call(&self, endpoint: &str, status: u16) {
        self.control_api_calls_total.with_label_values(&[endpoint, &status.to_string()]).inc();
    }

    /// Start timing an authentication validation
    pub fn start_validation_timer(&self, method: &str) -> prometheus::HistogramTimer {
        self.auth_validation_duration_seconds.with_label_values(&[method]).start_timer()
    }

    /// Start timing a Ledger key lookup operation
    pub fn start_ledger_key_lookup_timer(&self, result: &str) -> prometheus::HistogramTimer {
        self.ledger_key_lookup_duration_seconds.with_label_values(&[result]).start_timer()
    }

    /// Record a Ledger key lookup duration directly (in seconds)
    pub fn record_ledger_key_lookup_duration(&self, result: &str, duration_seconds: f64) {
        self.ledger_key_lookup_duration_seconds
            .with_label_values(&[result])
            .observe(duration_seconds);
    }

    /// Record a key validation failure with the specific reason
    ///
    /// Reasons: `inactive`, `revoked`, `not_yet_valid`, `expired`, `not_found`, `invalid_format`,
    /// `storage_error`
    pub fn record_key_validation_failure(&self, reason: &str) {
        self.key_validation_failures_total.with_label_values(&[reason]).inc();
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

/// Metrics trait for vault verification operations
///
/// This trait allows the vault verifier to record metrics without
/// depending on a specific metrics implementation.
pub trait VaultVerifierMetrics: Send + Sync {
    /// Record a cache hit
    fn record_cache_hit(&self, cache_type: &str);

    /// Record a cache miss
    fn record_cache_miss(&self, cache_type: &str);

    /// Record a cache invalidation
    fn record_cache_invalidation(&self, cache_type: &str, reason: &str);

    /// Record a control/ledger API call
    fn record_control_api_call(&self, operation: &str, status: u16);
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
