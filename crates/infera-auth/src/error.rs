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
            ErrorKind::InvalidIssuer => {
                AuthError::InvalidIssuer("Issuer validation failed".into())
            }
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
        let jwt_err = jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::ExpiredSignature
        );
        let auth_err: AuthError = jwt_err.into();

        assert!(matches!(auth_err, AuthError::TokenExpired));
    }
}
