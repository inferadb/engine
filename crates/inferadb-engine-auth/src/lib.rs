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
//! use inferadb_engine_auth::{AuthContext, jwt};
//!
//! // Decode and validate a JWT
//! let claims = jwt::decode_jwt_claims(token)?;
//! let org_id = claims.extract_org_id()?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Audit logging for authentication events
pub mod audit;
/// Certificate caching for Control
pub mod certificate_cache;
/// Control JWT authentication (reverse: Control -> Engine)
pub mod control_auth;
/// Authentication errors
pub mod error;
/// FDB-based Control JWT authentication
pub mod fdb_control_auth;
/// Axum extractors for authentication
pub mod extractor;
/// Internal service JWT authentication
pub mod internal;
/// JWKS caching and fetching
pub mod jwks_cache;
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
/// Enhanced JWT claim validation
pub mod validation;
/// Vault validation middleware
pub mod vault_middleware;

// Re-export key types from this crate
pub use audit::{AuditEvent, log_audit_event};
pub use certificate_cache::{
    CertificateCache, CertificateCacheError, KeyIdParseError, ParsedKeyId,
};
pub use control_auth::{
    AggregatedControlJwksCache, ControlContext, ControlJwk, ControlJwks, ControlJwksCache,
    aggregated_control_auth_middleware, control_auth_middleware,
};
pub use fdb_control_auth::FdbControlJwksCache;
pub use error::AuthError;
pub use extractor::{OptionalAuth, RequireAuth};
pub use internal::{InternalJwks, InternalJwksLoader};
pub use jwks_cache::{Jwk, JwksCache};
pub use metrics::AuthMetrics;
pub use middleware::{validate_vault_access, vault_validation_middleware};
pub use oauth::OAuthJwksClient;
pub use oidc::{OidcConfiguration, OidcDiscoveryClient};
pub use vault_middleware::vault_validation_middleware as enhanced_vault_validation_middleware;
