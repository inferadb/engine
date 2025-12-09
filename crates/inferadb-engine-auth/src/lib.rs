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
/// Certificate caching for Management API
pub mod certificate_cache;
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
/// Management API JWT authentication (reverse: Management -> Server)
pub mod management_auth;
/// Management API client
pub mod management_client;
/// Prometheus metrics for authentication operations
pub mod metrics;
/// Axum middleware for authentication
pub mod middleware;
/// OAuth 2.0 JWT validation
pub mod oauth;
/// OIDC Discovery client
pub mod oidc;
/// Server identity for server-to-management authentication
pub mod server_identity;
/// Enhanced JWT claim validation
pub mod validation;
/// Vault validation middleware
pub mod vault_middleware;
/// Vault verification against management API
pub mod vault_verification;

// Re-export key types
pub use audit::{AuditEvent, log_audit_event};
pub use certificate_cache::{
    CertificateCache, CertificateCacheError, KeyIdParseError, ParsedKeyId,
};
pub use error::AuthError;
pub use extractor::{OptionalAuth, RequireAuth};
pub use internal::{InternalJwks, InternalJwksLoader};
pub use jwks_cache::{Jwk, JwksCache};
pub use management_auth::{
    AggregatedManagementJwksCache, ManagementContext, ManagementJwk, ManagementJwks,
    ManagementJwksCache, aggregated_management_auth_middleware, management_auth_middleware,
};
pub use management_client::{
    ManagementApiError, ManagementClient, OrgStatus, OrganizationInfo, VaultInfo,
};
pub use metrics::AuthMetrics;
pub use middleware::{validate_vault_access, vault_validation_middleware};
pub use oauth::OAuthJwksClient;
pub use oidc::{OidcConfiguration, OidcDiscoveryClient};
pub use server_identity::{Jwks as ServerJwks, ServerIdentity, SharedServerIdentity};
pub use vault_middleware::vault_validation_middleware as enhanced_vault_validation_middleware;
pub use vault_verification::{
    ManagementApiVaultVerifier, NoOpVaultVerifier, VaultVerificationError, VaultVerifier,
};
