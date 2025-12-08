//! Configuration validation
//!
//! Validates configuration values and ensures consistency

use thiserror::Error;

use crate::{CacheConfig, Config, ObservabilityConfig, ServerConfig, StorageConfig};

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid address '{0}': {1}")]
    InvalidAddress(String, String),

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

/// Result type alias for validation operations
pub type Result<T> = std::result::Result<T, ValidationError>;

/// Validate complete configuration
pub fn validate(config: &Config) -> Result<()> {
    let mut errors = Vec::new();

    if let Err(e) = validate_server(&config.server) {
        errors.push(e);
    }

    if let Err(e) = validate_storage(&config.storage) {
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
pub fn validate_server(config: &ServerConfig) -> Result<()> {
    // Validate addresses are parseable as SocketAddr
    config
        .public_rest
        .parse::<std::net::SocketAddr>()
        .map_err(|e| ValidationError::InvalidAddress(config.public_rest.clone(), e.to_string()))?;
    config
        .public_grpc
        .parse::<std::net::SocketAddr>()
        .map_err(|e| ValidationError::InvalidAddress(config.public_grpc.clone(), e.to_string()))?;
    config
        .private_rest
        .parse::<std::net::SocketAddr>()
        .map_err(|e| ValidationError::InvalidAddress(config.private_rest.clone(), e.to_string()))?;

    // Validate worker threads
    if config.worker_threads == 0 {
        return Err(ValidationError::InvalidWorkerThreads(config.worker_threads));
    }

    Ok(())
}

/// Validate storage configuration
pub fn validate_storage(config: &StorageConfig) -> Result<()> {
    // Validate backend type
    match config.backend.as_str() {
        "memory" => {
            // Memory backend doesn't need cluster file
            Ok(())
        },
        "foundationdb" => {
            // FoundationDB requires cluster file
            if config.fdb_cluster_file.is_none() {
                return Err(ValidationError::MissingConnectionString(config.backend.clone()));
            }
            Ok(())
        },
        _ => Err(ValidationError::InvalidBackend(config.backend.clone())),
    }
}

/// Validate cache configuration
pub fn validate_cache(config: &CacheConfig) -> Result<()> {
    if config.enabled {
        // Validate capacity
        if config.max_capacity == 0 {
            return Err(ValidationError::InvalidCacheCapacity(config.max_capacity));
        }

        // Validate TTL
        if config.ttl == 0 {
            return Err(ValidationError::InvalidCacheTTL(config.ttl));
        }
    }

    Ok(())
}

/// Validate observability configuration
pub fn validate_observability(config: &ObservabilityConfig) -> Result<()> {
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
    fn test_validate_server_invalid_address() {
        let config = ServerConfig {
            public_rest: "invalid".to_string(),
            public_grpc: "0.0.0.0:8081".to_string(),
            private_rest: "0.0.0.0:8082".to_string(),
            worker_threads: 4,
        };
        assert!(matches!(validate_server(&config), Err(ValidationError::InvalidAddress(_, _))));
    }

    #[test]
    fn test_validate_server_invalid_workers() {
        let config = ServerConfig {
            public_rest: "0.0.0.0:8080".to_string(),
            public_grpc: "0.0.0.0:8081".to_string(),
            private_rest: "0.0.0.0:8082".to_string(),
            worker_threads: 0,
        };
        assert!(matches!(validate_server(&config), Err(ValidationError::InvalidWorkerThreads(0))));
    }

    #[test]
    fn test_validate_storage_memory_backend() {
        let config = StorageConfig { backend: "memory".to_string(), fdb_cluster_file: None };
        assert!(validate_storage(&config).is_ok());
    }

    #[test]
    fn test_validate_storage_foundationdb_without_cluster_file() {
        let config = StorageConfig { backend: "foundationdb".to_string(), fdb_cluster_file: None };
        assert!(matches!(
            validate_storage(&config),
            Err(ValidationError::MissingConnectionString(_))
        ));
    }

    #[test]
    fn test_validate_storage_foundationdb_with_cluster_file() {
        let config = StorageConfig {
            backend: "foundationdb".to_string(),
            fdb_cluster_file: Some("/etc/foundationdb/fdb.cluster".to_string()),
        };
        assert!(validate_storage(&config).is_ok());
    }

    #[test]
    fn test_validate_storage_invalid_backend() {
        let config = StorageConfig { backend: "redis".to_string(), fdb_cluster_file: None };
        assert!(matches!(validate_storage(&config), Err(ValidationError::InvalidBackend(_))));
    }

    #[test]
    fn test_validate_cache_zero_capacity() {
        let config = CacheConfig { enabled: true, max_capacity: 0, ttl: 300 };
        assert!(matches!(validate_cache(&config), Err(ValidationError::InvalidCacheCapacity(0))));
    }

    #[test]
    fn test_validate_cache_zero_ttl() {
        let config = CacheConfig { enabled: true, max_capacity: 10000, ttl: 0 };
        assert!(matches!(validate_cache(&config), Err(ValidationError::InvalidCacheTTL(0))));
    }

    #[test]
    fn test_validate_cache_disabled() {
        let config = CacheConfig { enabled: false, max_capacity: 0, ttl: 0 };
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
                public_rest: "invalid-address".to_string(),
                public_grpc: "0.0.0.0:8081".to_string(),
                private_rest: "0.0.0.0:8082".to_string(),
                worker_threads: 0,
            },
            storage: StorageConfig { backend: "invalid".to_string(), fdb_cluster_file: None },
            cache: CacheConfig { enabled: true, max_capacity: 0, ttl: 0 },
            observability: ObservabilityConfig {
                log_level: "invalid".to_string(),
                metrics_enabled: true,
                tracing_enabled: true,
            },
            auth: crate::AuthConfig::default(),
            identity: crate::IdentityConfig::default(),
            discovery: crate::DiscoveryConfig::default(),
            management_service: crate::ManagementServiceConfig::default(),
        };

        match validate(&config) {
            Err(ValidationError::Multiple(errors)) => {
                assert!(errors.len() > 1);
            },
            _ => panic!("Expected Multiple error"),
        }
    }
}
