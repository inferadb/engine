//! Configuration validation
//!
//! Validates configuration values and ensures consistency

use crate::{CacheConfig, Config, ObservabilityConfig, ServerConfig, StoreConfig};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid port number: {0}")]
    InvalidPort(u16),

    #[error("Invalid host: {0}")]
    InvalidHost(String),

    #[error("Invalid worker thread count: {0} (must be > 0)")]
    InvalidWorkerThreads(usize),

    #[error("Invalid cache capacity: {0} (must be > 0)")]
    InvalidCacheCapacity(u64),

    #[error("Invalid cache TTL: {0} (must be > 0)")]
    InvalidCacheTTL(u64),

    #[error("Invalid log level: {0} (must be one of: trace, debug, info, warn, error)")]
    InvalidLogLevel(String),

    #[error("Invalid backend: {0} (must be one of: memory, foundationdb)")]
    InvalidBackend(String),

    #[error("Missing connection string for backend: {0}")]
    MissingConnectionString(String),

    #[error("Multiple validation errors: {0:?}")]
    Multiple(Vec<ValidationError>),
}

/// Validation result type
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validate complete configuration
pub fn validate(config: &Config) -> ValidationResult<()> {
    let mut errors = Vec::new();

    if let Err(e) = validate_server(&config.server) {
        errors.push(e);
    }

    if let Err(e) = validate_store(&config.store) {
        errors.push(e);
    }

    if let Err(e) = validate_cache(&config.cache) {
        errors.push(e);
    }

    if let Err(e) = validate_observability(&config.observability) {
        errors.push(e);
    }

    if errors.is_empty() {
        Ok(())
    } else if errors.len() == 1 {
        Err(errors.into_iter().next().unwrap())
    } else {
        Err(ValidationError::Multiple(errors))
    }
}

/// Validate server configuration
pub fn validate_server(config: &ServerConfig) -> ValidationResult<()> {
    // Validate port (must be in valid range)
    if config.port == 0 {
        return Err(ValidationError::InvalidPort(config.port));
    }

    // Validate host (basic check for empty or invalid)
    if config.host.is_empty() {
        return Err(ValidationError::InvalidHost(config.host.clone()));
    }

    // Validate worker threads
    if config.worker_threads == 0 {
        return Err(ValidationError::InvalidWorkerThreads(config.worker_threads));
    }

    Ok(())
}

/// Validate store configuration
pub fn validate_store(config: &StoreConfig) -> ValidationResult<()> {
    // Validate backend type
    match config.backend.as_str() {
        "memory" => {
            // Memory backend doesn't need connection string
            Ok(())
        }
        "foundationdb" => {
            // FoundationDB requires connection string
            if config.connection_string.is_none() {
                return Err(ValidationError::MissingConnectionString(config.backend.clone()));
            }
            Ok(())
        }
        _ => Err(ValidationError::InvalidBackend(config.backend.clone())),
    }
}

/// Validate cache configuration
pub fn validate_cache(config: &CacheConfig) -> ValidationResult<()> {
    if config.enabled {
        // Validate capacity
        if config.max_capacity == 0 {
            return Err(ValidationError::InvalidCacheCapacity(config.max_capacity));
        }

        // Validate TTL
        if config.ttl_seconds == 0 {
            return Err(ValidationError::InvalidCacheTTL(config.ttl_seconds));
        }
    }

    Ok(())
}

/// Validate observability configuration
pub fn validate_observability(config: &ObservabilityConfig) -> ValidationResult<()> {
    // Validate log level
    match config.log_level.to_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(ValidationError::InvalidLogLevel(config.log_level.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_default_config() {
        let config = Config::default();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_validate_server_invalid_port() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            worker_threads: 4,
        };
        assert!(matches!(
            validate_server(&config),
            Err(ValidationError::InvalidPort(0))
        ));
    }

    #[test]
    fn test_validate_server_invalid_host() {
        let config = ServerConfig {
            host: "".to_string(),
            port: 8080,
            worker_threads: 4,
        };
        assert!(matches!(
            validate_server(&config),
            Err(ValidationError::InvalidHost(_))
        ));
    }

    #[test]
    fn test_validate_server_invalid_workers() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            worker_threads: 0,
        };
        assert!(matches!(
            validate_server(&config),
            Err(ValidationError::InvalidWorkerThreads(0))
        ));
    }

    #[test]
    fn test_validate_store_memory_backend() {
        let config = StoreConfig {
            backend: "memory".to_string(),
            connection_string: None,
        };
        assert!(validate_store(&config).is_ok());
    }

    #[test]
    fn test_validate_store_foundationdb_without_connection() {
        let config = StoreConfig {
            backend: "foundationdb".to_string(),
            connection_string: None,
        };
        assert!(matches!(
            validate_store(&config),
            Err(ValidationError::MissingConnectionString(_))
        ));
    }

    #[test]
    fn test_validate_store_foundationdb_with_connection() {
        let config = StoreConfig {
            backend: "foundationdb".to_string(),
            connection_string: Some("fdb:cluster".to_string()),
        };
        assert!(validate_store(&config).is_ok());
    }

    #[test]
    fn test_validate_store_invalid_backend() {
        let config = StoreConfig {
            backend: "redis".to_string(),
            connection_string: None,
        };
        assert!(matches!(
            validate_store(&config),
            Err(ValidationError::InvalidBackend(_))
        ));
    }

    #[test]
    fn test_validate_cache_zero_capacity() {
        let config = CacheConfig {
            enabled: true,
            max_capacity: 0,
            ttl_seconds: 300,
        };
        assert!(matches!(
            validate_cache(&config),
            Err(ValidationError::InvalidCacheCapacity(0))
        ));
    }

    #[test]
    fn test_validate_cache_zero_ttl() {
        let config = CacheConfig {
            enabled: true,
            max_capacity: 10000,
            ttl_seconds: 0,
        };
        assert!(matches!(
            validate_cache(&config),
            Err(ValidationError::InvalidCacheTTL(0))
        ));
    }

    #[test]
    fn test_validate_cache_disabled() {
        let config = CacheConfig {
            enabled: false,
            max_capacity: 0,
            ttl_seconds: 0,
        };
        // When disabled, zero values are acceptable
        assert!(validate_cache(&config).is_ok());
    }

    #[test]
    fn test_validate_observability_valid_log_levels() {
        for level in &["trace", "debug", "info", "warn", "error"] {
            let config = ObservabilityConfig {
                log_level: level.to_string(),
                metrics_enabled: true,
                tracing_enabled: true,
            };
            assert!(validate_observability(&config).is_ok());
        }
    }

    #[test]
    fn test_validate_observability_invalid_log_level() {
        let config = ObservabilityConfig {
            log_level: "invalid".to_string(),
            metrics_enabled: true,
            tracing_enabled: true,
        };
        assert!(matches!(
            validate_observability(&config),
            Err(ValidationError::InvalidLogLevel(_))
        ));
    }

    #[test]
    fn test_validate_multiple_errors() {
        let config = Config {
            server: ServerConfig {
                host: "".to_string(),
                port: 0,
                worker_threads: 0,
            },
            store: StoreConfig {
                backend: "invalid".to_string(),
                connection_string: None,
            },
            cache: CacheConfig {
                enabled: true,
                max_capacity: 0,
                ttl_seconds: 0,
            },
            observability: ObservabilityConfig {
                log_level: "invalid".to_string(),
                metrics_enabled: true,
                tracing_enabled: true,
            },
        };

        match validate(&config) {
            Err(ValidationError::Multiple(errors)) => {
                assert!(errors.len() > 1);
            }
            _ => panic!("Expected Multiple error"),
        }
    }
}
