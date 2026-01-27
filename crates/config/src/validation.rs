//! Configuration validation
//!
//! Validates configuration values and ensures consistency

use thiserror::Error;

use crate::{CacheConfig, Config, ListenConfig};

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid address '{0}': {1}")]
    InvalidAddress(String, String),

    #[error("Invalid thread count: {0} (must be > 0)")]
    InvalidThreads(usize),

    #[error("Invalid cache capacity: {0} (must be > 0)")]
    InvalidCacheCapacity(u64),

    #[error("Invalid cache TTL: {0} (must be > 0)")]
    InvalidCacheTTL(u64),

    #[error("Invalid log level: {0} (must be one of: trace, debug, info, warn, error)")]
    InvalidLogLevel(String),

    #[error("Invalid backend: {0} (must be one of: memory, ledger)")]
    InvalidBackend(String),

    #[error("Multiple validation errors: {0:?}")]
    Multiple(Vec<ValidationError>),
}

/// Result type alias for validation operations
pub type Result<T> = std::result::Result<T, ValidationError>;

/// Validate complete configuration
pub fn validate(config: &Config) -> Result<()> {
    let mut errors = Vec::new();

    if let Err(e) = validate_threads(config.threads) {
        errors.push(e);
    }

    if let Err(e) = validate_logging(&config.logging) {
        errors.push(e);
    }

    if let Err(e) = validate_listen(&config.listen) {
        errors.push(e);
    }

    if let Err(e) = validate_storage(&config.storage) {
        errors.push(e);
    }

    if let Err(e) = validate_cache(&config.cache) {
        errors.push(e);
    }

    match errors.len() {
        0 => Ok(()),
        1 => {
            // pop() is guaranteed to succeed since len() == 1
            match errors.pop() {
                Some(err) => Err(err),
                None => Err(ValidationError::Multiple(errors)),
            }
        },
        _ => Err(ValidationError::Multiple(errors)),
    }
}

/// Validate threads configuration
pub fn validate_threads(threads: usize) -> Result<()> {
    if threads == 0 {
        return Err(ValidationError::InvalidThreads(threads));
    }
    Ok(())
}

/// Validate logging level
pub fn validate_logging(level: &str) -> Result<()> {
    match level.to_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(ValidationError::InvalidLogLevel(level.to_string())),
    }
}

/// Validate listen configuration
pub fn validate_listen(config: &ListenConfig) -> Result<()> {
    // Validate addresses are parseable as SocketAddr
    config
        .http
        .parse::<std::net::SocketAddr>()
        .map_err(|e| ValidationError::InvalidAddress(config.http.clone(), e.to_string()))?;
    config
        .grpc
        .parse::<std::net::SocketAddr>()
        .map_err(|e| ValidationError::InvalidAddress(config.grpc.clone(), e.to_string()))?;

    Ok(())
}

/// Validate storage configuration
pub fn validate_storage(storage: &str) -> Result<()> {
    // Validate backend type
    match storage {
        "memory" | "ledger" => {
            // Valid backends
            Ok(())
        },
        "foundationdb" | "fdb" => {
            // FoundationDB has been removed - provide helpful error
            Err(ValidationError::InvalidBackend(format!(
                "{} (FoundationDB has been removed, migrate to 'ledger')",
                storage
            )))
        },
        _ => Err(ValidationError::InvalidBackend(storage.to_string())),
    }
}

/// Validate cache configuration
pub fn validate_cache(config: &CacheConfig) -> Result<()> {
    if config.enabled {
        // Validate capacity
        if config.capacity == 0 {
            return Err(ValidationError::InvalidCacheCapacity(config.capacity));
        }

        // Validate TTL
        if config.ttl == 0 {
            return Err(ValidationError::InvalidCacheTTL(config.ttl));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_default_config() {
        let config = Config::default();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_validate_threads_zero() {
        assert!(matches!(validate_threads(0), Err(ValidationError::InvalidThreads(0))));
    }

    #[test]
    fn test_validate_threads_valid() {
        assert!(validate_threads(4).is_ok());
    }

    #[test]
    fn test_validate_logging_valid_levels() {
        for level in &["trace", "debug", "info", "warn", "error"] {
            assert!(validate_logging(level).is_ok());
        }
    }

    #[test]
    fn test_validate_logging_invalid_level() {
        assert!(matches!(validate_logging("invalid"), Err(ValidationError::InvalidLogLevel(_))));
    }

    #[test]
    fn test_validate_listen_invalid_address() {
        let config = ListenConfig { http: "invalid".to_string(), grpc: "0.0.0.0:8081".to_string() };
        assert!(matches!(validate_listen(&config), Err(ValidationError::InvalidAddress(_, _))));
    }

    #[test]
    fn test_validate_listen_valid() {
        let config =
            ListenConfig { http: "0.0.0.0:8080".to_string(), grpc: "0.0.0.0:8081".to_string() };
        assert!(validate_listen(&config).is_ok());
    }

    #[test]
    fn test_validate_storage_memory_backend() {
        assert!(validate_storage("memory").is_ok());
    }

    #[test]
    fn test_validate_storage_ledger_backend() {
        assert!(validate_storage("ledger").is_ok());
    }

    #[test]
    fn test_validate_storage_foundationdb_rejected() {
        // FoundationDB has been removed - should return InvalidBackend with migration hint
        assert!(matches!(
            validate_storage("foundationdb"),
            Err(ValidationError::InvalidBackend(_))
        ));
    }

    #[test]
    fn test_validate_storage_fdb_rejected() {
        // FDB alias has been removed - should return InvalidBackend with migration hint
        assert!(matches!(validate_storage("fdb"), Err(ValidationError::InvalidBackend(_))));
    }

    #[test]
    fn test_validate_storage_invalid_backend() {
        assert!(matches!(validate_storage("redis"), Err(ValidationError::InvalidBackend(_))));
    }

    #[test]
    fn test_validate_cache_zero_capacity() {
        let config = CacheConfig { enabled: true, capacity: 0, ttl: 300 };
        assert!(matches!(validate_cache(&config), Err(ValidationError::InvalidCacheCapacity(0))));
    }

    #[test]
    fn test_validate_cache_zero_ttl() {
        let config = CacheConfig { enabled: true, capacity: 10000, ttl: 0 };
        assert!(matches!(validate_cache(&config), Err(ValidationError::InvalidCacheTTL(0))));
    }

    #[test]
    fn test_validate_cache_disabled() {
        let config = CacheConfig { enabled: false, capacity: 0, ttl: 0 };
        // When disabled, zero values are acceptable
        assert!(validate_cache(&config).is_ok());
    }

    #[test]
    fn test_validate_multiple_errors() {
        let config = Config {
            threads: 0,
            logging: "invalid".to_string(),
            listen: ListenConfig {
                http: "invalid-address".to_string(),
                grpc: "0.0.0.0:8081".to_string(),
            },
            storage: "invalid".to_string(),
            ledger: crate::LedgerConfig::default(),
            cache: CacheConfig { enabled: true, capacity: 0, ttl: 0 },
            token: crate::TokenConfig::default(),
            pem: None,
            replication: crate::ReplicationConfig::default(),
            schema: None,
        };

        match validate(&config) {
            Err(ValidationError::Multiple(errors)) => {
                assert!(errors.len() > 1);
            },
            _ => panic!("Expected Multiple error"),
        }
    }
}
