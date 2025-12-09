//! # InferaDB Engine Control Client
//!
//! HTTP client for Engine-to-Control communication.
//!
//! This crate provides the client infrastructure for the Engine to communicate
//! with the Control plane, including:
//!
//! - **ControlClient**: HTTP client for fetching organization and vault metadata
//! - **ServerIdentity**: Engine's Ed25519 keypair for signing JWTs
//! - **VaultVerifier**: Trait and implementation for vault/org verification with caching
//!
//! ## Example
//!
//! ```ignore
//! use inferadb_engine_control_client::{ControlClient, ServerIdentity, ControlVaultVerifier};
//!
//! // Create server identity for signing requests
//! let identity = ServerIdentity::generate();
//!
//! // Create Control client
//! let client = ControlClient::new(
//!     "https://api.inferadb.com".to_string(),
//!     None,
//!     5000,
//!     None,
//!     Some(Arc::new(identity)),
//! )?;
//!
//! // Verify vault ownership
//! let verifier = ControlVaultVerifier::new(Arc::new(client), cache_ttl, org_cache_ttl);
//! let vault_info = verifier.verify_vault(vault_id, org_id).await?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Control API client for fetching metadata
pub mod client;
/// Error types for Control client operations
pub mod error;
/// Server identity for JWT signing
pub mod identity;
/// Shared types for Control API responses
pub mod types;
/// Vault verification with caching
pub mod vault_verifier;

// Re-export key types at crate root
pub use client::ControlClient;
pub use error::ControlClientError;
pub use identity::{Jwk, Jwks, ServerIdentity, SharedServerIdentity};
pub use types::{OrgStatus, OrganizationInfo, VaultInfo};
pub use vault_verifier::{
    ControlVaultVerifier, NoOpVaultVerifier, VaultVerificationError, VaultVerifier,
};
