use thiserror::Error;

/// Authentication and authorization errors
#[derive(Debug, Error)]
pub enum AuthError {
    /// Malformed JWT - cannot be decoded
    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),

    /// Token has expired
    #[error("Token expired")]
    TokenExpired,

    /// Token not yet valid (nbf claim in future)
    #[error("Token not yet valid")]
    TokenNotYetValid,

    /// Signature verification failed
    #[error("Invalid signature")]
    InvalidSignature,

    /// Unknown or invalid issuer
    #[error("Invalid issuer: {0}")]
    InvalidIssuer(String),

    /// Audience doesn't match expected value
    #[error("Invalid audience: {0}")]
    InvalidAudience(String),

    /// Required claim is missing
    #[error("Missing claim: {0}")]
    MissingClaim(String),

    /// Scope validation failed
    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    /// Algorithm not in allowed list
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// JWKS-related errors
    #[error("JWKS error: {0}")]
    JwksError(String),

    /// OIDC discovery failed
    #[error("OIDC discovery failed: {0}")]
    OidcDiscoveryFailed(String),

    /// Token introspection failed
    #[error("Introspection failed: {0}")]
    IntrospectionFailed(String),

    /// Invalid introspection response
    #[error("Invalid introspection response: {0}")]
    InvalidIntrospectionResponse(String),

    /// Token is inactive (from introspection)
    #[error("Token is inactive")]
    TokenInactive,

    /// Required tenant_id claim missing from OAuth token
    #[error("Missing tenant_id claim in OAuth token")]
    MissingTenantId,

    /// Token replay detected (JTI already seen)
    #[error("Token replay detected")]
    ReplayDetected,

    /// Replay protection error
    #[error("Replay protection error: {0}")]
    ReplayProtectionError(String),

    /// Token too old (issued at exceeds max age)
    #[error("Token too old")]
    TokenTooOld,
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match err.kind() {
            ErrorKind::InvalidToken => {
                AuthError::InvalidTokenFormat("Invalid JWT structure".into())
            }
            ErrorKind::InvalidSignature => AuthError::InvalidSignature,
            ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
            ErrorKind::InvalidAudience => {
                AuthError::InvalidAudience("Audience validation failed".into())
            }
            ErrorKind::InvalidIssuer => AuthError::InvalidIssuer("Issuer validation failed".into()),
            ErrorKind::InvalidAlgorithm => {
                AuthError::UnsupportedAlgorithm("Algorithm not supported".into())
            }
            _ => AuthError::InvalidTokenFormat(format!("JWT error: {}", err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AuthError::InvalidTokenFormat("test".into());
        assert_eq!(err.to_string(), "Invalid token format: test");

        let err = AuthError::TokenExpired;
        assert_eq!(err.to_string(), "Token expired");

        let err = AuthError::MissingClaim("tenant_id".into());
        assert_eq!(err.to_string(), "Missing claim: tenant_id");
    }

    #[test]
    fn test_error_from_jsonwebtoken() {
        let jwt_err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
        let auth_err: AuthError = jwt_err.into();

        assert!(matches!(auth_err, AuthError::TokenExpired));
    }

    #[test]
    fn test_oauth_error_variants() {
        let err = AuthError::OidcDiscoveryFailed("endpoint not found".into());
        assert_eq!(err.to_string(), "OIDC discovery failed: endpoint not found");

        let err = AuthError::IntrospectionFailed("connection refused".into());
        assert_eq!(err.to_string(), "Introspection failed: connection refused");

        let err = AuthError::InvalidIntrospectionResponse("malformed JSON".into());
        assert_eq!(
            err.to_string(),
            "Invalid introspection response: malformed JSON"
        );

        let err = AuthError::TokenInactive;
        assert_eq!(err.to_string(), "Token is inactive");

        let err = AuthError::MissingTenantId;
        assert_eq!(err.to_string(), "Missing tenant_id claim in OAuth token");
    }
}
