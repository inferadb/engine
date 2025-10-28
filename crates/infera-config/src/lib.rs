//! # Infera Config - Configuration Management
//!
//! Handles configuration loading from files, environment variables, and CLI args.

use std::path::Path;

use config::{Config as ConfigBuilder, ConfigError, File, Environment};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub store: StoreConfig,
    pub cache: CacheConfig,
    pub observability: ObservabilityConfig,
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
