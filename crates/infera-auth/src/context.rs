use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication context extracted from validated JWT
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthContext {
    /// Tenant identifier (extracted from iss or tenant_id claim)
    pub tenant_id: String,

    /// Client identifier (from sub or client_id claim)
    pub client_id: String,

    /// Key ID used for verification (from kid header)
    pub key_id: String,

    /// Authentication method used
    pub auth_method: AuthMethod,

    /// Granted scopes
    pub scopes: Vec<String>,

    /// Token issued at timestamp
    pub issued_at: DateTime<Utc>,

    /// Token expiration timestamp
    pub expires_at: DateTime<Utc>,

    /// JWT ID for replay protection (optional)
    pub jti: Option<String>,

    /// Vault UUID for multi-tenancy isolation
    pub vault: Uuid,

    /// Account UUID (vault owner)
    pub account: Uuid,
}

/// Authentication method used to verify the token
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    /// Private-key JWT from tenant SDK/CLI
    PrivateKeyJwt,
    /// OAuth 2.0 access token
    OAuthAccessToken,
    /// Internal service JWT (Control Plane → PDP)
    InternalServiceJwt,
}

impl AuthContext {
    /// Check if the context has a required scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Check if the token is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Create a default AuthContext for when authentication is disabled
    /// Uses the provided default vault and account UUIDs
    pub fn default_unauthenticated(default_vault: Uuid, default_account: Uuid) -> Self {
        Self {
            tenant_id: "default".to_string(),
            client_id: "system:unauthenticated".to_string(),
            key_id: "default".to_string(),
            auth_method: AuthMethod::InternalServiceJwt,
            scopes: vec![
                "inferadb.check".to_string(),
                "inferadb.write".to_string(),
                "inferadb.expand".to_string(),
            ],
            issued_at: Utc::now(),
            // Set to far future so it never expires
            expires_at: DateTime::<Utc>::from_timestamp(i64::MAX / 1000, 0)
                .unwrap_or_else(Utc::now),
            jti: None,
            vault: default_vault,
            account: default_account,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_context(scopes: Vec<&str>, exp_offset_secs: i64) -> AuthContext {
        AuthContext {
            tenant_id: "test-tenant".into(),
            client_id: "test-client".into(),
            key_id: "test-key-1".into(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: scopes.into_iter().map(|s| s.to_string()).collect(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(exp_offset_secs),
            jti: Some("test-jti".into()),
            vault: Uuid::nil(),
            account: Uuid::nil(),
        }
    }

    #[test]
    fn test_has_scope_present() {
        let ctx = create_test_context(vec!["inferadb.check", "inferadb.write"], 300);

        assert!(ctx.has_scope("inferadb.check"));
        assert!(ctx.has_scope("inferadb.write"));
    }

    #[test]
    fn test_has_scope_absent() {
        let ctx = create_test_context(vec!["inferadb.check"], 300);

        assert!(!ctx.has_scope("inferadb.write"));
        assert!(!ctx.has_scope("inferadb.admin"));
    }

    #[test]
    fn test_has_scope_empty() {
        let ctx = create_test_context(vec![], 300);

        assert!(!ctx.has_scope("inferadb.check"));
    }

    #[test]
    fn test_is_valid_not_expired() {
        let ctx = create_test_context(vec!["inferadb.check"], 300);
        assert!(ctx.is_valid());
    }

    #[test]
    fn test_is_valid_expired() {
        let ctx = create_test_context(vec!["inferadb.check"], -60);
        assert!(!ctx.is_valid());
    }

    #[test]
    fn test_is_valid_just_expired() {
        let ctx = create_test_context(vec!["inferadb.check"], -1);
        assert!(!ctx.is_valid());
    }

    #[test]
    fn test_auth_method_equality() {
        assert_eq!(AuthMethod::PrivateKeyJwt, AuthMethod::PrivateKeyJwt);
        assert_eq!(AuthMethod::OAuthAccessToken, AuthMethod::OAuthAccessToken);
        assert_ne!(AuthMethod::PrivateKeyJwt, AuthMethod::OAuthAccessToken);
    }
}
