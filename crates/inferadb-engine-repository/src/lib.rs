//! Repository layer for Engine storage operations.
//!
//! This crate provides domain-specific repositories that sit on top of
//! the generic [`StorageBackend`] abstraction. Each repository encapsulates
//! the key encoding, serialization, and transaction logic for its entity type.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │                  Service Layer                   │
//! │           (Engine API handlers)                  │
//! ├──────────────────────────────────────────────────┤
//! │                Repository Layer                  │
//! │  OrganizationRepository  │  VaultRepository      │
//! │  RelationshipRepository                          │
//! │     (Domain logic, serialization, indexing)      │
//! ├──────────────────────────────────────────────────┤
//! │              inferadb-storage                    │
//! │            StorageBackend trait                  │
//! │   (get, set, delete, get_range, transaction)     │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! # Repositories
//!
//! - [`OrganizationRepository`] - CRUD operations for organizations
//! - [`VaultRepository`] - CRUD operations for vaults and system configuration
//! - [`RelationshipRepository`] - Authorization graph operations with versioning
//!
//! # Key Encoding
//!
//! All repositories use a consistent key schema with the `engine:` prefix.
//! The [`keys`] module provides functions for building these keys.
//!
//! # Error Handling
//!
//! All repository operations return [`RepositoryResult<T>`], which maps
//! storage errors to domain-appropriate error types.
//!
//! # Example
//!
//! ```ignore
//! use inferadb_storage::MemoryBackend;
//! use inferadb_engine_repository::{OrganizationRepository, VaultRepository};
//!
//! // Create repositories with a shared backend
//! let backend = MemoryBackend::new();
//! let orgs = OrganizationRepository::new(backend.clone());
//! let vaults = VaultRepository::new(backend);
//! ```

#![deny(unsafe_code)]

pub mod error;
pub mod keys;
pub mod organization;
pub mod relationship;
pub mod storage;
pub mod store_impl;
pub mod vault;

// Re-export main types for convenience
pub use error::{RepositoryError, RepositoryResult};
pub use organization::OrganizationRepository;
pub use relationship::RelationshipRepository;
pub use storage::EngineStorage;
pub use vault::VaultRepository;
