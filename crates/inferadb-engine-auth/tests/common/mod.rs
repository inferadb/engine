#![allow(dead_code)]

pub mod internal_jwt_helpers;
pub mod mock_jwks;
pub mod mock_management;
pub mod mock_oauth;

use chrono::{Duration, Utc};
use inferadb_engine_types::{AuthContext, AuthMethod};

/// Create a test AuthContext without JWT validation
///
/// Returns a pre-configured AuthContext suitable for testing without
/// needing to generate and validate actual JWTs.
///
/// # Example
///
/// ```
/// let auth = test_auth_context();
/// assert_eq!(auth.organization, 12345);
/// assert!(auth.has_scope("inferadb.check"));
/// ```
pub fn test_auth_context() -> AuthContext {
    AuthContext {
        client_id: "test-client".to_string(),
        key_id: "test-key-1".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: vec!["inferadb.check".to_string(), "inferadb.write".to_string()],
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        jti: Some("test-jti-123".to_string()),
        vault: 1,
        organization: 12345,
    }
}

/// Create a test AuthContext with custom organization and scopes
///
/// # Arguments
///
/// * `org_id` - The organization ID (Snowflake ID)
/// * `scopes` - List of scopes to grant
///
/// # Example
///
/// ```
/// let auth = test_auth_context_with(98765, vec!["inferadb.check"]);
/// assert_eq!(auth.organization, 98765);
/// assert!(auth.has_scope("inferadb.check"));
/// ```
pub fn test_auth_context_with(org_id: i64, scopes: Vec<&str>) -> AuthContext {
    AuthContext {
        client_id: format!("client-{}", org_id),
        key_id: format!("key-{}", org_id),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        jti: Some(uuid::Uuid::new_v4().to_string()),
        vault: 1,
        organization: org_id,
    }
}

/// Create a test AuthContext with OAuth authentication method
///
/// # Arguments
///
/// * `org_id` - The organization ID (Snowflake ID)
/// * `scopes` - List of scopes to grant
///
/// # Example
///
/// ```
/// let auth = test_oauth_context(98765, vec!["inferadb.check"]);
/// assert_eq!(auth.auth_method, AuthMethod::OAuthAccessToken);
/// ```
pub fn test_oauth_context(org_id: i64, scopes: Vec<&str>) -> AuthContext {
    AuthContext {
        client_id: format!("oauth-{}", org_id),
        key_id: "oauth-key-1".to_string(),
        auth_method: AuthMethod::OAuthAccessToken,
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        jti: Some(uuid::Uuid::new_v4().to_string()),
        vault: 1,
        organization: org_id,
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
        client_id: "test-client".to_string(),
        key_id: "test-key-1".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: vec!["inferadb.check".to_string()],
        issued_at: Utc::now() - Duration::hours(2),
        expires_at: Utc::now() - Duration::hours(1),
        jti: Some("expired-jti".to_string()),
        vault: 1,
        organization: 12345,
    }
}
