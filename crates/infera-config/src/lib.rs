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

    /// Internal JWKS file path (optional)
    pub internal_jwks_path: Option<PathBuf>,

    /// Internal JWKS environment variable name (optional)
    pub internal_jwks_env: Option<String>,

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
            internal_jwks_path: None,
            internal_jwks_env: Some("INFERADB_INTERNAL_JWKS".to_string()),
            redis_url: None,
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
}
