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

/// Authentication context and types
pub mod context;
/// Authentication errors
pub mod error;
/// Axum extractors for authentication
pub mod extractor;
/// JWT validation and claims
pub mod jwt;
/// JWKS caching and fetching
pub mod jwks_cache;
/// Axum middleware for authentication
pub mod middleware;
/// OAuth 2.0 JWT validation
pub mod oauth;
/// OIDC Discovery client
pub mod oidc;
/// Internal service JWT authentication
pub mod internal;
/// Audit logging for authentication events
pub mod audit;

// Re-export key types
pub use context::{AuthContext, AuthMethod};
pub use error::AuthError;
pub use extractor::{OptionalAuth, RequireAuth};
pub use jwks_cache::{Jwk, JwksCache};
pub use oauth::OAuthJwksClient;
pub use oidc::{OidcConfiguration, OidcDiscoveryClient};
pub use internal::{InternalJwks, InternalJwksLoader};
pub use audit::{AuditEvent, log_audit_event};
