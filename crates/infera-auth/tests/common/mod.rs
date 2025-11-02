#![allow(dead_code)]

pub mod internal_jwt_helpers;
pub mod mock_jwks;
pub mod mock_oauth;

use chrono::{Duration, Utc};
use infera_auth::{AuthContext, AuthMethod};

/// Create a test AuthContext without JWT validation
///
/// Returns a pre-configured AuthContext suitable for testing without
/// needing to generate and validate actual JWTs.
///
/// # Example
///
/// ```
/// let auth = test_auth_context();
/// assert_eq!(auth.tenant_id, "test-tenant");
/// assert!(auth.has_scope("inferadb.check"));
/// ```
pub fn test_auth_context() -> AuthContext {
    AuthContext {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        key_id: "test-key-1".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: vec!["inferadb.check".to_string(), "inferadb.write".to_string()],
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        jti: Some("test-jti-123".to_string()),
    }
}

/// Create a test AuthContext with custom tenant and scopes
///
/// # Arguments
///
/// * `tenant_id` - The tenant identifier
/// * `scopes` - List of scopes to grant
///
/// # Example
///
/// ```
/// let auth = test_auth_context_with("acme", vec!["inferadb.check"]);
/// assert_eq!(auth.tenant_id, "acme");
/// assert!(auth.has_scope("inferadb.check"));
/// ```
pub fn test_auth_context_with(tenant_id: &str, scopes: Vec<&str>) -> AuthContext {
    AuthContext {
        tenant_id: tenant_id.to_string(),
        client_id: format!("{}-client", tenant_id),
        key_id: format!("{}-key-1", tenant_id),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        jti: Some(uuid::Uuid::new_v4().to_string()),
    }
}

/// Create a test AuthContext with OAuth authentication method
///
/// # Arguments
///
/// * `tenant_id` - The tenant identifier
/// * `scopes` - List of scopes to grant
///
/// # Example
///
/// ```
/// let auth = test_oauth_context("acme", vec!["inferadb.check"]);
/// assert_eq!(auth.auth_method, AuthMethod::OAuthAccessToken);
/// ```
pub fn test_oauth_context(tenant_id: &str, scopes: Vec<&str>) -> AuthContext {
    AuthContext {
        tenant_id: tenant_id.to_string(),
        client_id: format!("oauth-{}", tenant_id),
        key_id: "oauth-key-1".to_string(),
        auth_method: AuthMethod::OAuthAccessToken,
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        jti: Some(uuid::Uuid::new_v4().to_string()),
    }
}

/// Create an expired test AuthContext for testing expiration handling
///
/// # Example
///
/// ```
/// let auth = test_expired_context();
/// assert!(!auth.is_valid());
/// ```
pub fn test_expired_context() -> AuthContext {
    AuthContext {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        key_id: "test-key-1".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: vec!["inferadb.check".to_string()],
        issued_at: Utc::now() - Duration::hours(2),
        expires_at: Utc::now() - Duration::hours(1),
        jti: Some("expired-jti".to_string()),
    }
}
