//! # Infera Config - Configuration Management
//!
//! Handles configuration loading from files, environment variables, and CLI args.

pub mod hot_reload;
pub mod secrets;
pub mod validation;

use std::path::{Path, PathBuf};

use config::{Config as ConfigBuilder, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub store: StoreConfig,
    pub cache: CacheConfig,
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    #[serde(default = "default_rate_limiting_enabled")]
    pub rate_limiting_enabled: bool,
}

fn default_rate_limiting_enabled() -> bool {
    true // Enabled by default for production safety
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_worker_threads() -> usize {
    num_cpus::get()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_backend")]
    pub backend: String,

    pub connection_string: Option<String>,
}

fn default_backend() -> String {
    "memory".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,

    #[serde(default = "default_cache_max_capacity")]
    pub max_capacity: u64,

    #[serde(default = "default_cache_ttl_seconds")]
    pub ttl_seconds: u64,
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_max_capacity() -> u64 {
    10_000
}

fn default_cache_ttl_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,

    #[serde(default = "default_tracing_enabled")]
    pub tracing_enabled: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_tracing_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable authentication (false for development/testing)
    #[serde(default = "default_auth_enabled")]
    pub enabled: bool,

    /// JWKS cache TTL in seconds
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl: u64,

    /// Accepted signature algorithms
    #[serde(default = "default_accepted_algorithms")]
    pub accepted_algorithms: Vec<String>,

    /// Enforce audience validation
    #[serde(default = "default_enforce_audience")]
    pub enforce_audience: bool,

    /// Expected audience value
    #[serde(default = "default_audience")]
    pub audience: String,

    /// Enforce scope validation
    #[serde(default = "default_enforce_scopes")]
    pub enforce_scopes: bool,

    /// Enable replay protection (requires Redis)
    #[serde(default = "default_replay_protection")]
    pub replay_protection: bool,

    /// Control Plane JWKS base URL
    #[serde(default = "default_jwks_base_url")]
    pub jwks_base_url: String,

    /// OAuth introspection endpoint (optional)
    pub oauth_introspection_endpoint: Option<String>,

    /// OAuth introspection client ID for authentication (optional)
    pub oauth_introspection_client_id: Option<String>,

    /// OAuth introspection client secret for authentication (optional)
    pub oauth_introspection_client_secret: Option<String>,

    /// OIDC discovery cache TTL in seconds
    #[serde(default = "default_oidc_discovery_cache_ttl")]
    pub oidc_discovery_cache_ttl: u64,

    /// OAuth introspection result cache TTL in seconds
    #[serde(default = "default_introspection_cache_ttl")]
    pub introspection_cache_ttl: u64,

    /// Internal JWKS file path (optional)
    pub internal_jwks_path: Option<PathBuf>,

    /// Internal JWKS environment variable name (optional)
    pub internal_jwks_env: Option<String>,

    /// Internal JWT issuer
    #[serde(default = "default_internal_issuer")]
    pub internal_issuer: String,

    /// Internal JWT audience
    #[serde(default = "default_internal_audience")]
    pub internal_audience: String,

    /// Redis URL for replay protection (optional)
    pub redis_url: Option<String>,

    /// Clock skew tolerance in seconds (for timestamp validation)
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: Option<u64>,

    /// Maximum token age in seconds (from iat to now)
    #[serde(default = "default_max_token_age_seconds")]
    pub max_token_age_seconds: Option<u64>,

    /// Issuer allowlist (if set, only these issuers are accepted)
    pub issuer_allowlist: Option<Vec<String>>,

    /// Issuer blocklist (these issuers are always rejected)
    pub issuer_blocklist: Option<Vec<String>>,

    /// Allowed audience values (for audience validation)
    #[serde(default = "default_allowed_audiences")]
    pub allowed_audiences: Vec<String>,

    /// Require JTI claim in all tokens
    #[serde(default = "default_require_jti")]
    pub require_jti: bool,

    /// Enable OAuth token validation
    #[serde(default = "default_oauth_enabled")]
    pub oauth_enabled: bool,

    /// OIDC discovery URL (for OAuth providers)
    pub oidc_discovery_url: Option<String>,

    /// OIDC client ID
    pub oidc_client_id: Option<String>,

    /// OIDC client secret
    pub oidc_client_secret: Option<String>,

    /// OAuth introspection URL
    pub introspection_url: Option<String>,

    /// Required scopes for authorization
    #[serde(default = "default_required_scopes")]
    pub required_scopes: Vec<String>,

    /// JWKS URL (alternative to jwks_base_url)
    #[serde(default = "default_jwks_url")]
    pub jwks_url: String,
}

fn default_auth_enabled() -> bool {
    false // Disabled by default for development
}

fn default_jwks_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_accepted_algorithms() -> Vec<String> {
    vec!["EdDSA".to_string(), "RS256".to_string()]
}

fn default_enforce_audience() -> bool {
    true
}

fn default_audience() -> String {
    "https://api.inferadb.com/evaluate".to_string()
}

fn default_enforce_scopes() -> bool {
    true
}

fn default_clock_skew_seconds() -> Option<u64> {
    Some(60) // 1 minute tolerance for clock differences
}

fn default_max_token_age_seconds() -> Option<u64> {
    Some(86400) // 24 hours maximum token age
}

fn default_allowed_audiences() -> Vec<String> {
    vec!["https://api.inferadb.com/evaluate".to_string()]
}

fn default_require_jti() -> bool {
    false // Optional by default, but required when replay_protection is enabled
}

fn default_oauth_enabled() -> bool {
    false
}

fn default_required_scopes() -> Vec<String> {
    vec![]
}

fn default_jwks_url() -> String {
    String::new()
}

fn default_replay_protection() -> bool {
    false
}

fn default_jwks_base_url() -> String {
    "https://auth.inferadb.com/.well-known".to_string()
}

fn default_oidc_discovery_cache_ttl() -> u64 {
    86400 // 24 hours in seconds
}

fn default_introspection_cache_ttl() -> u64 {
    60 // 1 minute in seconds
}

fn default_internal_issuer() -> String {
    "https://internal.inferadb.com".to_string()
}

fn default_internal_audience() -> String {
    "https://api.inferadb.com/internal".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_auth_enabled(),
            jwks_cache_ttl: default_jwks_cache_ttl(),
            accepted_algorithms: default_accepted_algorithms(),
            enforce_audience: default_enforce_audience(),
            audience: default_audience(),
            enforce_scopes: default_enforce_scopes(),
            replay_protection: default_replay_protection(),
            jwks_base_url: default_jwks_base_url(),
            oauth_introspection_endpoint: None,
            oauth_introspection_client_id: None,
            oauth_introspection_client_secret: None,
            oidc_discovery_cache_ttl: default_oidc_discovery_cache_ttl(),
            introspection_cache_ttl: default_introspection_cache_ttl(),
            internal_jwks_path: None,
            internal_jwks_env: Some("INFERADB_INTERNAL_JWKS".to_string()),
            internal_issuer: default_internal_issuer(),
            internal_audience: default_internal_audience(),
            redis_url: None,
            clock_skew_seconds: default_clock_skew_seconds(),
            max_token_age_seconds: default_max_token_age_seconds(),
            issuer_allowlist: None,
            issuer_blocklist: None,
            allowed_audiences: default_allowed_audiences(),
            require_jti: default_require_jti(),
            oauth_enabled: default_oauth_enabled(),
            oidc_discovery_url: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            introspection_url: None,
            required_scopes: default_required_scopes(),
            jwks_url: default_jwks_url(),
        }
    }
}

impl AuthConfig {
    /// Log startup warnings about authentication configuration
    ///
    /// Should be called at application startup to warn about development-mode settings.
    pub fn log_startup_warnings(&self) {
        if !self.enabled {
            tracing::warn!(
                "⚠️  AUTHENTICATION IS DISABLED ⚠️\n\
                 \n\
                 This configuration is ONLY safe for local development and testing.\n\
                 DO NOT use this configuration in production environments.\n\
                 \n\
                 To enable authentication, set: auth.enabled = true\n\
                 "
            );
        }
    }

    /// Validate the authentication configuration and log warnings for potential issues
    ///
    /// This method performs comprehensive validation of security-related settings:
    /// - Checks for forbidden algorithms (symmetric algorithms, "none")
    /// - Validates replay protection configuration
    /// - Warns about overly permissive clock skew settings
    /// - Validates issuer and audience configuration
    /// - Ensures required JTI when replay protection is enabled
    pub fn validate(&self) -> Result<(), String> {
        // Log startup warnings
        self.log_startup_warnings();

        // Warn if authentication is enabled but JWKS base URL is missing
        if self.enabled && self.jwks_base_url.is_empty() && self.jwks_url.is_empty() {
            tracing::warn!(
                "Authentication is enabled but jwks_base_url and jwks_url are empty. \
                 Tenant JWT authentication will not work."
            );
        }

        // Warn if internal JWT sources are configured but both are missing
        let has_internal_path = self.internal_jwks_path.is_some();
        let has_internal_env = self.internal_jwks_env.is_some();

        if !has_internal_path && !has_internal_env {
            tracing::info!(
                "No internal JWT JWKS source configured. \
                 Internal service-to-service authentication will not be available. \
                 Set internal_jwks_path or internal_jwks_env to enable."
            );
        }

        // CRITICAL: Reject if accepted_algorithms is empty
        if self.accepted_algorithms.is_empty() {
            return Err(
                "accepted_algorithms cannot be empty. At least one algorithm must be configured."
                    .to_string(),
            );
        }

        // CRITICAL: Reject if accepted_algorithms contains forbidden algorithms
        const FORBIDDEN: &[&str] = &["none", "HS256", "HS384", "HS512"];
        for alg in &self.accepted_algorithms {
            if FORBIDDEN.contains(&alg.as_str()) {
                return Err(format!(
                    "Algorithm '{}' is forbidden for security reasons (symmetric or none). \
                     Only asymmetric algorithms (EdDSA, RS256, ES256, etc.) are allowed.",
                    alg
                ));
            }
        }

        // CRITICAL: Reject if replay_protection enabled but no redis_url
        if self.replay_protection && self.redis_url.is_none() {
            return Err(
                "replay_protection is enabled but redis_url is not configured. \
                 Either disable replay_protection or configure redis_url."
                    .to_string(),
            );
        }

        // Warn if replay protection is enabled with require_jti false
        if self.replay_protection && !self.require_jti {
            tracing::warn!(
                "replay_protection is enabled but require_jti is false. \
                 Tokens without JTI will fail validation. Consider setting require_jti=true."
            );
        }

        // Warn if using in-memory replay protection (when Redis is not configured)
        if self.replay_protection && self.redis_url.is_none() {
            tracing::warn!(
                "In-memory replay protection is NOT suitable for multi-node deployments. \
                 Configure redis_url for production use."
            );
        }

        // Warn if clock skew is too permissive (> 5 minutes)
        if let Some(skew) = self.clock_skew_seconds {
            if skew > 300 {
                tracing::warn!(
                    clock_skew = %skew,
                    "Clock skew tolerance is very high (> 5 minutes). \
                     This may allow expired tokens to be accepted. \
                     Recommended: 60 seconds or less."
                );
            }
        }

        // Warn if audience validation is disabled
        if !self.enforce_audience {
            tracing::warn!(
                "Audience validation is disabled. This is a security risk. \
                 Tokens intended for other services may be accepted. \
                 Set enforce_audience=true for production."
            );
        }

        // Warn if allowed_audiences is empty but enforce_audience is true
        if self.enforce_audience && self.allowed_audiences.is_empty() {
            tracing::warn!(
                "Audience enforcement is enabled but allowed_audiences is empty. \
                 All tokens will be rejected due to audience mismatch."
            );
        }

        // Info about issuer validation
        if self.issuer_allowlist.is_some() {
            tracing::info!(
                "Issuer allowlist is configured. Only tokens from allowed issuers will be accepted."
            );
        }

        if self.issuer_blocklist.is_some() {
            tracing::info!(
                "Issuer blocklist is configured. Tokens from blocked issuers will be rejected."
            );
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: default_host(),
                port: default_port(),
                worker_threads: default_worker_threads(),
                rate_limiting_enabled: default_rate_limiting_enabled(),
            },
            store: StoreConfig {
                backend: default_backend(),
                connection_string: None,
            },
            cache: CacheConfig {
                enabled: default_cache_enabled(),
                max_capacity: default_cache_max_capacity(),
                ttl_seconds: default_cache_ttl_seconds(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
            },
            auth: AuthConfig::default(),
        }
    }
}

/// Load configuration from file and environment
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let builder = ConfigBuilder::builder()
        .add_source(File::from(path.as_ref()).required(false))
        .add_source(Environment::with_prefix("INFERA").separator("__"))
        .build()?;

    builder.try_deserialize()
}

/// Load configuration with defaults
pub fn load_or_default<P: AsRef<Path>>(path: P) -> Config {
    load(path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_auth_config_validation_enabled_without_jwks_url() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let mut config = AuthConfig::default();
        config.enabled = true;
        config.jwks_base_url = String::new();

        // Should warn but not panic
        config.validate();
    }

    #[test]
    fn test_auth_config_validation_no_internal_jwks_source() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        let mut config = AuthConfig::default();
        config.internal_jwks_path = None;
        config.internal_jwks_env = None;

        // Should log info but not panic
        config.validate();
    }

    #[test]
    fn test_auth_config_validation_replay_protection_without_redis() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let mut config = AuthConfig::default();
        config.replay_protection = true;
        config.redis_url = None;

        // Should warn but not panic
        config.validate();
    }

    #[test]
    fn test_auth_config_validation_no_accepted_algorithms() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let mut config = AuthConfig::default();
        config.accepted_algorithms = vec![];

        // Should warn but not panic
        config.validate();
    }

    #[test]
    fn test_auth_config_validation_valid_config() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        let config = AuthConfig {
            enabled: true,
            jwks_base_url: "https://auth.example.com".to_string(),
            internal_jwks_env: Some("JWKS_ENV".to_string()),
            replay_protection: false,
            accepted_algorithms: vec!["EdDSA".to_string()],
            ..Default::default()
        };

        // Should not log any warnings
        config.validate();
    }
}
