//! # Infera Repl - Replication and Consistency Management
//!
//! Handles replication, revision tokens, and consistency management.

use thiserror::Error;

pub mod token;
pub mod snapshot;
pub mod change_feed;

pub use token::RevisionToken;
pub use change_feed::{Change, ChangeFeed, ChangeStream, Operation, ChangeFilter, ChangeMetadata, ChangeFeedConfig};

#[derive(Debug, Error)]
pub enum ReplError {
    #[error("Conflict detected")]
    Conflict,

    #[error("Invalid revision token")]
    InvalidRevision,

    #[error("Replication error: {0}")]
    Replication(String),

    #[error("Store error: {0}")]
    Store(#[from] infera_store::StoreError),
}

pub type Result<T> = std::result::Result<T, ReplError>;
