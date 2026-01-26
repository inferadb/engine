//! Storage factory for creating backend instances
//!
//! Provides a flexible way to instantiate different storage backends
//! without exposing implementation details to consumers.
//!
//! ## Using the Repository Pattern
//!
//! For the memory backend and Ledger backend, use `EngineStorage<S>` from
//! `inferadb-engine-repository` directly:
//!
//! ```ignore
//! use inferadb_engine_repository::EngineStorage;
//! use inferadb_storage::MemoryBackend;
//!
//! // Memory backend
//! let store: Arc<dyn InferaStore> = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
//!
//! // Ledger backend
//! use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig};
//!
//! let config = LedgerBackendConfig::builder()
//!     .endpoints(vec!["http://localhost:50051".to_string()])
//!     .client_id("my-service")
//!     .namespace_id(1)
//!     .build()?;
//! let backend = LedgerBackend::new(config).await?;
//! let store: Arc<dyn InferaStore> = Arc::new(EngineStorage::builder().backend(backend).build());
//! ```

use std::{str::FromStr, sync::Arc};

use crate::{InferaStore, Result, StoreError};

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// In-memory storage (for testing and development)
    /// Use `EngineStorage<MemoryBackend>` from `inferadb-engine-repository`
    Memory,
}

impl FromStr for BackendType {
    type Err = StoreError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "memory" => Ok(BackendType::Memory),
            _ => Err(StoreError::Internal(format!("Unknown backend type: {}", s))),
        }
    }
}

impl BackendType {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendType::Memory => "memory",
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
        Self { backend: BackendType::Memory, connection_string: None }
    }
}

impl StorageConfig {
    /// Create config for memory backend
    pub fn memory() -> Self {
        Self { backend: BackendType::Memory, connection_string: None }
    }
}

/// Storage factory for creating backend instances
///
/// Note: For memory backend and Ledger backend, use `EngineStorage<S>` directly.
/// See module documentation for examples.
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend from configuration
    ///
    /// Note: For Memory and Ledger backends, use `EngineStorage<S>` from
    /// `inferadb-engine-repository` directly. See module documentation for examples.
    pub async fn create(config: StorageConfig) -> Result<Arc<dyn InferaStore>> {
        match config.backend {
            BackendType::Memory => Err(StoreError::Internal(
                "Memory backend not available via factory. Use EngineStorage<MemoryBackend> from inferadb-engine-repository instead.".to_string()
            )),
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

    /// Create a storage backend from string configuration with handle
    ///
    /// Returns `(store, None)` since there is no longer a separate database handle.
    ///
    /// For memory backend, use `EngineStorage<MemoryBackend>` directly instead.
    pub async fn from_str_with_handle(
        backend_str: &str,
        _connection_string: Option<String>,
    ) -> Result<(Arc<dyn InferaStore>, Option<std::sync::Arc<()>>)> {
        let backend_type = BackendType::from_str(backend_str)?;
        match backend_type {
            BackendType::Memory => Err(StoreError::Internal(
                "Memory backend not available via factory. Use EngineStorage<MemoryBackend> from inferadb-engine-repository instead.".to_string()
            )),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_type_from_str() {
        assert_eq!(BackendType::from_str("memory").unwrap(), BackendType::Memory);
        assert_eq!(BackendType::from_str("Memory").unwrap(), BackendType::Memory);
        assert_eq!(BackendType::from_str("MEMORY").unwrap(), BackendType::Memory);

        assert!(BackendType::from_str("invalid").is_err());
    }

    #[test]
    fn test_backend_type_as_str() {
        assert_eq!(BackendType::Memory.as_str(), "memory");
    }
}
