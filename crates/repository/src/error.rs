//! Repository error types for Engine storage operations.
//!
//! This module provides a [`RepositoryError`] enum that wraps storage-level errors
//! and adds domain-specific error variants for repository operations.

use inferadb_common_storage::StorageError;

/// Result type alias for repository operations.
pub type RepositoryResult<T> = Result<T, RepositoryError>;

/// Errors that can occur during repository operations.
///
/// This enum maps [`StorageError`] variants to repository-level semantics
/// and adds additional variants for domain-specific error conditions.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    /// The requested entity was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// An entity with the same identifier already exists.
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// Transaction conflict due to concurrent modification.
    ///
    /// The operation should typically be retried.
    #[error("Conflict: concurrent modification detected")]
    Conflict,

    /// Serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Validation of input data failed.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Storage backend connection or communication error.
    #[error("Storage connection error: {0}")]
    Connection(String),

    /// Operation timed out.
    #[error("Operation timed out")]
    Timeout,

    /// Internal error in the repository layer.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<StorageError> for RepositoryError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound { key, .. } => RepositoryError::NotFound(key),
            StorageError::Conflict => RepositoryError::Conflict,
            StorageError::Connection { message, .. } => RepositoryError::Connection(message),
            StorageError::Serialization { message, .. } => RepositoryError::Serialization(message),
            StorageError::Timeout => RepositoryError::Timeout,
            StorageError::Internal { message, .. } => RepositoryError::Internal(message),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_error_conversion() {
        let storage_err = StorageError::not_found("test_key");
        let repo_err: RepositoryError = storage_err.into();
        assert!(matches!(repo_err, RepositoryError::NotFound(_)));

        let storage_err = StorageError::conflict();
        let repo_err: RepositoryError = storage_err.into();
        assert!(matches!(repo_err, RepositoryError::Conflict));

        let storage_err = StorageError::timeout();
        let repo_err: RepositoryError = storage_err.into();
        assert!(matches!(repo_err, RepositoryError::Timeout));
    }

    #[test]
    fn test_error_display() {
        let err = RepositoryError::NotFound("org:123".to_string());
        assert_eq!(err.to_string(), "Not found: org:123");

        let err = RepositoryError::AlreadyExists("vault:456".to_string());
        assert_eq!(err.to_string(), "Already exists: vault:456");

        let err = RepositoryError::Conflict;
        assert_eq!(err.to_string(), "Conflict: concurrent modification detected");
    }
}
