//! OpenTelemetry Tracing Configuration
//!
//! This module provides configuration for exporting authentication spans to OpenTelemetry.
//! It follows OpenTelemetry semantic conventions for authentication events.
//!
//! ## Semantic Conventions
//!
//! Authentication spans use the following semantic convention attributes:
//! - `auth.method` - Authentication method (PrivateKeyJwt, OAuthAccessToken, InternalServiceJwt)
//! - `auth.org_id` - Tenant identifier
//! - `auth.scopes` - Comma-separated list of scopes
//! - `auth.result` - Authentication result (success/failure)
//! - `auth.error_type` - Error type if authentication failed
//!
//! ## Sampling
//!
//! Authentication spans use the following sampling strategy:
//! - Always sample authentication failures (for security monitoring)
//! - Parent-based sampling for successes (follow parent span sampling decision)
//!
//! ## Usage
//!
//! ```ignore
//! use inferadb_engine_observe::tracing_config::configure_auth_span_export;
//!
//! // Configure OpenTelemetry export
//! configure_auth_span_export("http://localhost:4317")?;
//! ```

use std::collections::HashMap;

/// Semantic convention for authentication method
pub const AUTH_METHOD: &str = "auth.method";

/// Semantic convention for tenant ID
pub const AUTH_TENANT_ID: &str = "auth.org_id";

/// Semantic convention for authentication scopes
pub const AUTH_SCOPES: &str = "auth.scopes";

/// Semantic convention for authentication result
pub const AUTH_RESULT: &str = "auth.result";

/// Semantic convention for authentication error type
pub const AUTH_ERROR_TYPE: &str = "auth.error_type";

/// OpenTelemetry configuration for authentication spans
#[derive(Debug, Clone)]
pub struct OTelAuthConfig {
    /// OTLP endpoint URL (e.g., "http://localhost:4317")
    pub endpoint: String,

    /// Whether to always sample authentication failures
    pub always_sample_failures: bool,

    /// Service name for OpenTelemetry
    pub service_name: String,

    /// Additional resource attributes
    pub resource_attributes: HashMap<String, String>,
}

impl Default for OTelAuthConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            always_sample_failures: true,
            service_name: "inferadb-engine".to_string(),
            resource_attributes: HashMap::new(),
        }
    }
}

impl OTelAuthConfig {
    /// Create a new OpenTelemetry configuration
    pub fn new(endpoint: String) -> Self {
        Self { endpoint, ..Default::default() }
    }

    /// Set service name
    pub fn with_service_name(mut self, service_name: String) -> Self {
        self.service_name = service_name;
        self
    }

    /// Set whether to always sample failures
    pub fn with_always_sample_failures(mut self, always_sample: bool) -> Self {
        self.always_sample_failures = always_sample;
        self
    }

    /// Add a resource attribute
    pub fn with_resource_attribute(mut self, key: String, value: String) -> Self {
        self.resource_attributes.insert(key, value);
        self
    }
}

/// Apply semantic conventions to an authentication span
///
/// This function adds OpenTelemetry semantic convention attributes to a span.
///
/// # Arguments
///
/// * `span` - The tracing span to annotate
/// * `method` - Authentication method
/// * `org_id` - Tenant identifier (optional)
/// * `scopes` - List of scopes (optional)
/// * `result` - Authentication result ("success" or "failure")
/// * `error_type` - Error type if authentication failed (optional)
pub fn apply_auth_semantic_conventions(
    span: &tracing::Span,
    method: &str,
    org_id: Option<&str>,
    scopes: Option<&[String]>,
    result: &str,
    error_type: Option<&str>,
) {
    span.record(AUTH_METHOD, method);
    span.record(AUTH_RESULT, result);

    if let Some(tid) = org_id {
        span.record(AUTH_TENANT_ID, tid);
    }

    if let Some(s) = scopes {
        span.record(AUTH_SCOPES, s.join(",").as_str());
    }

    if let Some(err) = error_type {
        span.record(AUTH_ERROR_TYPE, err);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_otel_auth_config_default() {
        let config = OTelAuthConfig::default();

        assert_eq!(config.endpoint, "http://localhost:4317");
        assert!(config.always_sample_failures);
        assert_eq!(config.service_name, "inferadb-engine");
        assert!(config.resource_attributes.is_empty());
    }

    #[test]
    fn test_otel_auth_config_builder() {
        let config = OTelAuthConfig::new("http://otel-collector:4317".to_string())
            .with_service_name("test-service".to_string())
            .with_always_sample_failures(false)
            .with_resource_attribute("env".to_string(), "production".to_string());

        assert_eq!(config.endpoint, "http://otel-collector:4317");
        assert!(!config.always_sample_failures);
        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.resource_attributes.get("env"), Some(&"production".to_string()));
    }

    #[test]
    fn test_semantic_conventions_constants() {
        assert_eq!(AUTH_METHOD, "auth.method");
        assert_eq!(AUTH_TENANT_ID, "auth.org_id");
        assert_eq!(AUTH_SCOPES, "auth.scopes");
        assert_eq!(AUTH_RESULT, "auth.result");
        assert_eq!(AUTH_ERROR_TYPE, "auth.error_type");
    }

    #[test]
    fn test_apply_auth_semantic_conventions_success() {
        let span = tracing::info_span!(
            "test_auth",
            auth.method = tracing::field::Empty,
            auth.org_id = tracing::field::Empty,
            auth.scopes = tracing::field::Empty,
            auth.result = tracing::field::Empty,
        );

        apply_auth_semantic_conventions(
            &span,
            "tenant_jwt",
            Some("acme"),
            Some(&["read".to_string(), "write".to_string()]),
            "success",
            None,
        );

        // Span should have all fields recorded
        // (We can't easily assert on span fields in tests, but this verifies the function doesn't
        // panic)
    }

    #[test]
    fn test_apply_auth_semantic_conventions_failure() {
        let span = tracing::info_span!(
            "test_auth",
            auth.method = tracing::field::Empty,
            auth.result = tracing::field::Empty,
            auth.error_type = tracing::field::Empty,
        );

        apply_auth_semantic_conventions(
            &span,
            "tenant_jwt",
            None,
            None,
            "failure",
            Some("expired"),
        );

        // Span should have fields recorded
    }

    #[test]
    fn test_apply_auth_semantic_conventions_minimal() {
        let span = tracing::info_span!(
            "test_auth",
            auth.method = tracing::field::Empty,
            auth.result = tracing::field::Empty,
        );

        apply_auth_semantic_conventions(&span, "internal_jwt", None, None, "success", None);

        // Should not panic with minimal fields
    }
}
