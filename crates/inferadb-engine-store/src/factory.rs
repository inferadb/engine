//! Storage factory for creating backend instances
//!
//! Provides a flexible way to instantiate different storage backends
//! without exposing implementation details to consumers.
//!
//! ## Migration to Repository Pattern
//!
//! For the memory backend and Ledger backend, use `EngineStorage<S>` from
//! `inferadb-engine-repository` directly:
//!
//! ```ignore
//! use inferadb_engine_repository::EngineStorage;
//! use inferadb_storage::MemoryBackend;
//!
//! // Memory backend
//! let store: Arc<dyn InferaStore> = Arc::new(EngineStorage::new(MemoryBackend::new()));
//!
//! // Ledger backend
//! use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig};
//!
//! let config = LedgerBackendConfig::builder()
//!     .with_endpoint("http://localhost:50051")
//!     .with_client_id("my-service")
//!     .with_namespace_id(1)
//!     .build()?;
//! let backend = LedgerBackend::new(config).await?;
//! let store: Arc<dyn InferaStore> = Arc::new(EngineStorage::new(backend));
//! ```
//!
//! The factory still supports FoundationDB which uses a monolithic implementation.

use std::{str::FromStr, sync::Arc};

#[cfg(feature = "fdb")]
use crate::foundationdb::FoundationDBBackend;
use crate::{InferaStore, Result, StoreError};

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// In-memory storage (for testing and development)
    /// Use `EngineStorage<MemoryBackend>` from `inferadb-engine-repository`
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
    /// Optional connection string (for database backends like FDB)
    pub connection_string: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self { backend: BackendType::Memory, connection_string: None }
    }
}

impl StorageConfig {
    /// Create config for memory backend
    pub fn memory() -> Self {
        Self { backend: BackendType::Memory, connection_string: None }
    }

    /// Create config for FoundationDB backend
    #[cfg(feature = "fdb")]
    pub fn foundationdb(connection_string: Option<String>) -> Self {
        Self { backend: BackendType::FoundationDB, connection_string }
    }
}

/// Storage factory for creating backend instances
///
/// Note: For memory backend, use `EngineStorage<MemoryBackend>` directly.
/// This factory still supports FoundationDB backend creation.
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend from configuration
    ///
    /// For memory backend and Ledger backend, use `EngineStorage<S>` directly instead.
    #[cfg(feature = "fdb")]
    pub async fn create(config: StorageConfig) -> Result<Arc<dyn InferaStore>> {
        match config.backend {
            BackendType::Memory => {
                Err(StoreError::Internal(
                    "Memory backend not available via factory. Use EngineStorage<MemoryBackend> from inferadb-engine-repository instead.".to_string()
                ))
            },
            BackendType::FoundationDB => {
                let backend = if let Some(cluster_file) = config.connection_string.as_deref() {
                    FoundationDBBackend::with_cluster_file(Some(cluster_file)).await?
                } else {
                    FoundationDBBackend::new().await?
                };
                Ok(Arc::new(backend) as Arc<dyn InferaStore>)
            },
        }
    }

    /// Create a storage backend from configuration (non-FDB version)
    ///
    /// Note: For Memory and Ledger backends, use `EngineStorage<S>` from
    /// `inferadb-engine-repository` directly. See module documentation for examples.
    #[cfg(not(feature = "fdb"))]
    pub async fn create(config: StorageConfig) -> Result<Arc<dyn InferaStore>> {
        match config.backend {
            BackendType::Memory => {
                Err(StoreError::Internal(
                    "Memory backend not available via factory. Use EngineStorage<MemoryBackend> from inferadb-engine-repository instead.".to_string()
                ))
            },
        }
    }

    /// Create a storage backend from string configuration
    ///
    /// For memory backend, use `EngineStorage<MemoryBackend>` directly instead.
    pub async fn from_str(
        backend_str: &str,
        connection_string: Option<String>,
    ) -> Result<Arc<dyn InferaStore>> {
        let backend_type = BackendType::from_str(backend_str)?;
        let config = StorageConfig { backend: backend_type, connection_string };
        Self::create(config).await
    }

    /// Create a storage backend from string configuration, returning the FDB database handle if
    /// available.
    ///
    /// Returns `(store, Some(fdb_database))` for FDB backends.
    /// This is used for FDB-based cross-service communication like cache invalidation.
    ///
    /// For memory backend, use `EngineStorage<MemoryBackend>` directly instead.
    #[cfg(feature = "fdb")]
    pub async fn from_str_with_fdb(
        backend_str: &str,
        connection_string: Option<String>,
    ) -> Result<(Arc<dyn InferaStore>, Option<std::sync::Arc<foundationdb::Database>>)> {
        let backend_type = BackendType::from_str(backend_str)?;
        match backend_type {
            BackendType::Memory => {
                Err(StoreError::Internal(
                    "Memory backend not available via factory. Use EngineStorage<MemoryBackend> from inferadb-engine-repository instead.".to_string()
                ))
            },
            BackendType::FoundationDB => {
                let backend = if let Some(cluster_file) = connection_string.as_deref() {
                    FoundationDBBackend::with_cluster_file(Some(cluster_file)).await?
                } else {
                    FoundationDBBackend::new().await?
                };
                let db = backend.database();
                Ok((Arc::new(backend) as Arc<dyn InferaStore>, Some(db)))
            },
        }
    }

    /// Create a storage backend from string configuration (non-FDB version)
    #[cfg(not(feature = "fdb"))]
    pub async fn from_str_with_fdb(
        backend_str: &str,
        _connection_string: Option<String>,
    ) -> Result<(Arc<dyn InferaStore>, Option<std::sync::Arc<()>>)> {
        let backend_type = BackendType::from_str(backend_str)?;
        match backend_type {
            BackendType::Memory => {
                Err(StoreError::Internal(
                    "Memory backend not available via factory. Use EngineStorage<MemoryBackend> from inferadb-engine-repository instead.".to_string()
                ))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_type_from_str() {
        assert_eq!(BackendType::from_str("memory").unwrap(), BackendType::Memory);
        assert_eq!(BackendType::from_str("Memory").unwrap(), BackendType::Memory);
        assert_eq!(BackendType::from_str("MEMORY").unwrap(), BackendType::Memory);

        #[cfg(feature = "fdb")]
        {
            assert_eq!(BackendType::from_str("foundationdb").unwrap(), BackendType::FoundationDB);
            assert_eq!(BackendType::from_str("fdb").unwrap(), BackendType::FoundationDB);
            assert_eq!(BackendType::from_str("FoundationDB").unwrap(), BackendType::FoundationDB);
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
    #[cfg(feature = "fdb")]
    #[ignore] // Requires FDB running
    async fn test_factory_create_fdb() {
        let config = StorageConfig::foundationdb(None);
        let store = StorageFactory::create(config).await;

        // Should either succeed or fail with connection error
        match store {
            Ok(s) => {
                let test_vault = 11111111111111i64;
                let _rev = s.get_revision(test_vault).await.unwrap();
                // Successfully got revision
            },
            Err(e) => {
                // Expected if FDB is not running
                assert!(matches!(e, StoreError::Database(_)));
            },
        }
    }
}
