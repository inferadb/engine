//! # Infera Store - Storage Abstraction Layer
//!
//! Provides abstract database operations and revision consistency management.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod memory;
#[cfg(feature = "fdb")]
pub mod foundationdb;

pub use memory::MemoryBackend;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Not found")]
    NotFound,

    #[error("Conflict")]
    Conflict,

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// A revision/version token for consistent reads
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Revision(pub u64);

impl Revision {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

/// A tuple key for lookups
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TupleKey {
    pub object: String,
    pub relation: String,
    pub user: Option<String>,
}

/// A relationship tuple
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tuple {
    pub object: String,
    pub relation: String,
    pub user: String,
}

/// Abstract tuple store interface
#[async_trait]
pub trait TupleStore: Send + Sync {
    /// Read tuples matching the key at a specific revision
    async fn read(&self, key: &TupleKey, revision: Revision) -> Result<Vec<Tuple>>;

    /// Write tuples and return the new revision
    async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision>;

    /// Get the current revision
    async fn get_revision(&self) -> Result<Revision>;

    /// Delete tuples matching the key
    async fn delete(&self, key: &TupleKey) -> Result<Revision>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revision_ordering() {
        let r1 = Revision(1);
        let r2 = Revision(2);
        assert!(r1 < r2);
        assert_eq!(r1.next(), r2);
    }
}
