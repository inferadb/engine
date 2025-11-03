//! # InferaDB Authentication
//!
//! This crate provides authentication and authorization for the InferaDB Core Server (PDP).
//!
//! ## Features
//!
//! - **Private-Key JWT (RFC 7523)**: Tenant SDK/CLI authentication
//! - **OAuth 2.0 Bearer Tokens (RFC 6749)**: Dashboard & enterprise authentication
//! - **Internal Service JWT**: Control Plane → PDP authentication
//!
//! ## Security
//!
//! - Only asymmetric algorithms (EdDSA, RS256) are supported
//! - Symmetric algorithms (HS256, etc.) are explicitly rejected
//! - No unsafe code is allowed in this crate
//!
//! ## Example
//!
//! ```ignore
//! use infera_auth::{AuthContext, jwt};
//!
//! // Decode and validate a JWT
//! let claims = jwt::decode_jwt_claims(token)?;
//! let tenant_id = claims.extract_tenant_id()?;
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
/// JWKS caching and fetching
pub mod jwks_cache;
/// JWT validation and claims
pub mod jwt;
/// Axum middleware for authentication
pub mod middleware;
/// OAuth 2.0 JWT validation
pub mod oauth;
/// OIDC Discovery client
pub mod oidc;
/// Replay protection for JWT tokens
pub mod replay;
/// Enhanced JWT claim validation
pub mod validation;

// Re-export key types
pub use audit::{AuditEvent, log_audit_event};
pub use error::AuthError;
pub use extractor::{OptionalAuth, RequireAuth};
pub use internal::{InternalJwks, InternalJwksLoader};
pub use jwks_cache::{Jwk, JwksCache};
pub use middleware::{
    validate_vault_access, validate_vault_access_with_store, vault_validation_middleware,
};
pub use oauth::OAuthJwksClient;
pub use oidc::{OidcConfiguration, OidcDiscoveryClient};
#[cfg(feature = "replay-protection")]
pub use replay::RedisReplayProtection;
pub use replay::{InMemoryReplayProtection, ReplayProtection};
