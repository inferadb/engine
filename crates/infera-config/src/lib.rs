//! # Infera Config - Configuration Management
//!
//! Handles configuration loading from files, environment variables, and CLI args.

pub mod secrets;
pub mod validation;

use std::path::{Path, PathBuf};

use config::{Config as ConfigBuilder, ConfigError, File, Environment};
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
        }
    }
}

impl AuthConfig {
    /// Validate the authentication configuration and log warnings for potential issues
    pub fn validate(&self) {
        // Warn if authentication is enabled but JWKS base URL is missing
        if self.enabled && self.jwks_base_url.is_empty() {
            tracing::warn!(
                "Authentication is enabled but jwks_base_url is empty. \
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

        // Warn if replay protection is enabled but Redis URL is missing
        if self.replay_protection && self.redis_url.is_none() {
            tracing::warn!(
                "Replay protection is enabled but redis_url is not configured. \
                 Replay protection will not function."
            );
        }

        // Info about accepted algorithms
        if self.accepted_algorithms.is_empty() {
            tracing::warn!(
                "No accepted signature algorithms configured. \
                 All JWT signatures will be rejected."
            );
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: default_host(),
                port: default_port(),
                worker_threads: default_worker_threads(),
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
