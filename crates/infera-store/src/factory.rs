//! Storage factory for creating backend instances
//!
//! Provides a flexible way to instantiate different storage backends
//! without exposing implementation details to consumers.

use crate::memory::MemoryBackend;
use crate::{Result, StoreError, TupleStore};
use std::str::FromStr;
use std::sync::Arc;

#[cfg(feature = "fdb")]
use crate::foundationdb::FoundationDBBackend;

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// In-memory storage (for testing and development)
    Memory,
    /// FoundationDB storage (for production)
    #[cfg(feature = "fdb")]
    FoundationDB,
}

impl FromStr for BackendType {
    type Err = StoreError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "memory" => Ok(BackendType::Memory),
            #[cfg(feature = "fdb")]
            "foundationdb" | "fdb" => Ok(BackendType::FoundationDB),
            _ => Err(StoreError::Internal(format!("Unknown backend type: {}", s))),
        }
    }
}

impl BackendType {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendType::Memory => "memory",
            #[cfg(feature = "fdb")]
            BackendType::FoundationDB => "foundationdb",
        }
    }
}

/// Configuration for storage backend
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Backend type to use
    pub backend: BackendType,
    /// Optional connection string (for database backends)
    pub connection_string: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: BackendType::Memory,
            connection_string: None,
        }
    }
}

impl StorageConfig {
    /// Create config for memory backend
    pub fn memory() -> Self {
        Self {
            backend: BackendType::Memory,
            connection_string: None,
        }
    }

    /// Create config for FoundationDB backend
    #[cfg(feature = "fdb")]
    pub fn foundationdb(connection_string: Option<String>) -> Self {
        Self {
            backend: BackendType::FoundationDB,
            connection_string,
        }
    }
}

/// Storage factory for creating backend instances
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend from configuration
    pub async fn create(config: StorageConfig) -> Result<Arc<dyn TupleStore>> {
        match config.backend {
            BackendType::Memory => Ok(Arc::new(MemoryBackend::new()) as Arc<dyn TupleStore>),
            #[cfg(feature = "fdb")]
            BackendType::FoundationDB => {
                let backend = if let Some(cluster_file) = config.connection_string.as_deref() {
                    FoundationDBBackend::with_cluster_file(Some(cluster_file)).await?
                } else {
                    FoundationDBBackend::new().await?
                };
                Ok(Arc::new(backend) as Arc<dyn TupleStore>)
            }
        }
    }

    /// Create a storage backend from string configuration
    pub async fn from_str(
        backend_str: &str,
        connection_string: Option<String>,
    ) -> Result<Arc<dyn TupleStore>> {
        let backend_type = BackendType::from_str(backend_str)?;
        let config = StorageConfig {
            backend: backend_type,
            connection_string,
        };
        Self::create(config).await
    }

    /// Create default memory backend
    pub fn memory() -> Arc<dyn TupleStore> {
        Arc::new(MemoryBackend::new()) as Arc<dyn TupleStore>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_type_from_str() {
        assert_eq!(
            BackendType::from_str("memory").unwrap(),
            BackendType::Memory
        );
        assert_eq!(
            BackendType::from_str("Memory").unwrap(),
            BackendType::Memory
        );
        assert_eq!(
            BackendType::from_str("MEMORY").unwrap(),
            BackendType::Memory
        );

        #[cfg(feature = "fdb")]
        {
            assert_eq!(
                BackendType::from_str("foundationdb").unwrap(),
                BackendType::FoundationDB
            );
            assert_eq!(
                BackendType::from_str("fdb").unwrap(),
                BackendType::FoundationDB
            );
            assert_eq!(
                BackendType::from_str("FoundationDB").unwrap(),
                BackendType::FoundationDB
            );
        }

        assert!(BackendType::from_str("invalid").is_err());
    }

    #[test]
    fn test_backend_type_as_str() {
        assert_eq!(BackendType::Memory.as_str(), "memory");

        #[cfg(feature = "fdb")]
        assert_eq!(BackendType::FoundationDB.as_str(), "foundationdb");
    }

    #[tokio::test]
    async fn test_factory_create_memory() {
        let config = StorageConfig::memory();
        let store = StorageFactory::create(config).await.unwrap();

        // Verify it works
        let rev = store.get_revision().await.unwrap();
        assert_eq!(rev, crate::Revision::zero());
    }

    #[tokio::test]
    async fn test_factory_from_str_memory() {
        let store = StorageFactory::from_str("memory", None).await.unwrap();

        // Verify it works
        let rev = store.get_revision().await.unwrap();
        assert_eq!(rev, crate::Revision::zero());
    }

    #[tokio::test]
    async fn test_factory_memory_shorthand() {
        let store = StorageFactory::memory();

        // Verify it works
        let rev = store.get_revision().await.unwrap();
        assert_eq!(rev, crate::Revision::zero());
    }

    #[tokio::test]
    #[cfg(feature = "fdb")]
    #[ignore] // Requires FDB running
    async fn test_factory_create_fdb() {
        let config = StorageConfig::foundationdb(None);
        let store = StorageFactory::create(config).await;

        // Should either succeed or fail with connection error
        match store {
            Ok(s) => {
                let rev = s.get_revision().await.unwrap();
                assert!(rev.0 >= 0);
            }
            Err(e) => {
                // Expected if FDB is not running
                assert!(matches!(e, StoreError::Database(_)));
            }
        }
    }
}
