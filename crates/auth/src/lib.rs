//! # InferaDB Authentication
//!
//! This crate provides authentication and authorization for the InferaDB Core Server (PDP).
//!
//! ## Features
//!
//! - **Ledger-Backed Token Validation**: Keys fetched from distributed ledger
//! - **Private-Key JWT (RFC 7523)**: Tenant SDK/CLI authentication
//! - **OAuth 2.0 Bearer Tokens (RFC 6749)**: Dashboard & enterprise authentication
//!
//! ## Security
//!
//! - Only asymmetric algorithms (EdDSA) are supported for signing keys
//! - Symmetric algorithms (HS256, etc.) are explicitly rejected
//! - No unsafe code is allowed in this crate
//!
//! ## Example
//!
//! ```ignore
//! use inferadb_engine_auth::{SigningKeyCache, jwt};
//!
//! // Decode and validate a JWT using Ledger-backed cache
//! let claims = jwt::decode_jwt_claims(token)?;
//! let org_id = claims.extract_org_id()?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Audit logging for authentication events
pub mod audit;
/// Authentication errors
pub mod error;
/// Axum extractors for authentication
pub mod extractor;
/// Internal service JWT authentication
pub mod internal;
/// JWT validation and claims
pub mod jwt;
/// Prometheus metrics for authentication operations
pub mod metrics;
/// Axum middleware for authentication
pub mod middleware;
/// OAuth 2.0 JWT validation
pub mod oauth;
/// OIDC Discovery client
pub mod oidc;
/// Ledger-backed signing key cache
pub mod signing_key_cache;
/// Enhanced JWT claim validation
pub mod validation;
/// Vault validation middleware
pub mod vault_middleware;

// Re-export key types from this crate
pub use audit::{AuditEvent, log_audit_event};
pub use error::AuthError;
pub use extractor::{OptionalAuth, RequireAuth};
pub use internal::{InternalJwks, InternalJwksLoader};
pub use metrics::{AuthMetrics, VaultVerifierMetrics};
pub use middleware::{
    ledger_auth_middleware, ledger_auth_middleware_with_metrics, validate_vault_access,
    vault_validation_middleware,
};
pub use oauth::{Jwk, OAuthJwksClient};
pub use oidc::{OidcConfiguration, OidcDiscoveryClient};
pub use signing_key_cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SigningKeyCache};
pub use vault_middleware::{
    LedgerVaultVerifier, VaultInfo, VaultVerificationError, VaultVerifier,
    control_verified_vault_middleware,
};
