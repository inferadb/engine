use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
