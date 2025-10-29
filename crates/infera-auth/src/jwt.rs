use crate::error::AuthError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer
    pub iss: String,
    /// Subject
    pub sub: String,
    /// Audience
    pub aud: String,
    /// Expiration time (seconds since epoch)
    pub exp: u64,
    /// Issued at (seconds since epoch)
    pub iat: u64,
    /// Not before (optional, seconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// JWT ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Space-separated scopes
    pub scope: String,
    /// Tenant ID (for OAuth tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl JwtClaims {
    /// Extract tenant ID from claims
    /// For tenant JWTs: parse from "tenant:acme" format in iss
    /// For OAuth tokens: use tenant_id claim
    pub fn extract_tenant_id(&self) -> Result<String, AuthError> {
        // First check explicit tenant_id claim (OAuth tokens)
        if let Some(ref tenant_id) = self.tenant_id {
            if !tenant_id.is_empty() {
                return Ok(tenant_id.clone());
            }
        }

        // Fall back to parsing from issuer (tenant JWTs)
        if let Some(tenant) = self.iss.strip_prefix("tenant:") {
            if !tenant.is_empty() {
                return Ok(tenant.to_string());
            }
        }

        Err(AuthError::MissingClaim(
            "tenant_id (could not extract from iss or tenant_id claim)".into(),
        ))
    }

    /// Parse scopes from space-separated string
    pub fn parse_scopes(&self) -> Vec<String> {
        self.scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }
}

/// Decode JWT header without verification
pub fn decode_jwt_header(token: &str) -> Result<Header, AuthError> {
    decode_header(token).map_err(|e| {
        AuthError::InvalidTokenFormat(format!("Failed to decode JWT header: {}", e))
    })
}

/// Decode JWT claims without verification (used to extract issuer for JWKS lookup)
pub fn decode_jwt_claims(token: &str) -> Result<JwtClaims, AuthError> {
    // Split token into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::InvalidTokenFormat(
            "JWT must have 3 parts separated by dots".into(),
        ));
    }

    // Decode payload (part 1) using base64 URL-safe encoding
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| {
            AuthError::InvalidTokenFormat(format!("Failed to decode JWT payload: {}", e))
        })?;

    // Parse as JSON
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes).map_err(|e| {
        AuthError::InvalidTokenFormat(format!("Failed to parse JWT claims: {}", e))
    })?;

    // Validate required claims are present
    if claims.iss.is_empty() {
        return Err(AuthError::MissingClaim("iss".into()));
    }
    if claims.sub.is_empty() {
        return Err(AuthError::MissingClaim("sub".into()));
    }
    if claims.aud.is_empty() {
        return Err(AuthError::MissingClaim("aud".into()));
    }

    Ok(claims)
}

/// Validate JWT claims (timestamp and audience checks)
pub fn validate_claims(claims: &JwtClaims, expected_audience: Option<&str>) -> Result<(), AuthError> {
    let now = Utc::now().timestamp() as u64;

    // Check expiration
    if claims.exp <= now {
        return Err(AuthError::TokenExpired);
    }

    // Check not-before if present
    if let Some(nbf) = claims.nbf {
        if nbf > now {
            return Err(AuthError::TokenNotYetValid);
        }
    }

    // Check issued-at is reasonable (not too far in past, max 24 hours)
    if claims.iat > now {
        return Err(AuthError::InvalidTokenFormat(
            "iat claim is in the future".into(),
        ));
    }
    if now - claims.iat > 86400 {
        // 24 hours
        return Err(AuthError::InvalidTokenFormat(
            "iat claim is too old (> 24 hours)".into(),
        ));
    }

    // Check audience if enforced
    if let Some(expected) = expected_audience {
        if claims.aud != expected {
            return Err(AuthError::InvalidAudience(format!(
                "expected '{}', got '{}'",
                expected, claims.aud
            )));
        }
    }

    Ok(())
}

/// Validate algorithm is in allowed list and not symmetric
pub fn validate_algorithm(alg: &str, accepted_algorithms: &[String]) -> Result<(), AuthError> {
    // Always reject symmetric algorithms
    const FORBIDDEN: &[&str] = &["HS256", "HS384", "HS512", "none"];
    if FORBIDDEN.contains(&alg) {
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not allowed for security reasons",
            alg
        )));
    }

    // Check if in accepted list
    if !accepted_algorithms.iter().any(|a| a == alg) {
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not in accepted list",
            alg
        )));
    }

    Ok(())
}

/// Verify JWT signature with a public key (placeholder - will be enhanced with JWKS in Phase 2)
pub fn verify_signature(
    token: &str,
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<JwtClaims, AuthError> {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false; // We do custom validation
    validation.validate_nbf = false;
    validation.validate_aud = false;

    let token_data = decode::<JwtClaims>(token, key, &validation)?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tenant_id_from_issuer() {
        let claims = JwtClaims {
            iss: "tenant:acme".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check".into(),
            tenant_id: None,
        };

        assert_eq!(claims.extract_tenant_id().unwrap(), "acme");
    }

    #[test]
    fn test_extract_tenant_id_from_claim() {
        let claims = JwtClaims {
            iss: "https://auth.example.com".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check".into(),
            tenant_id: Some("acme".into()),
        };

        assert_eq!(claims.extract_tenant_id().unwrap(), "acme");
    }

    #[test]
    fn test_extract_tenant_id_missing() {
        let claims = JwtClaims {
            iss: "https://auth.example.com".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check".into(),
            tenant_id: None,
        };

        assert!(claims.extract_tenant_id().is_err());
    }

    #[test]
    fn test_parse_scopes() {
        let claims = JwtClaims {
            iss: "tenant:acme".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check inferadb.write inferadb.expand".into(),
            tenant_id: None,
        };

        let scopes = claims.parse_scopes();
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&"inferadb.check".to_string()));
        assert!(scopes.contains(&"inferadb.write".to_string()));
        assert!(scopes.contains(&"inferadb.expand".to_string()));
    }

    #[test]
    fn test_parse_scopes_empty() {
        let claims = JwtClaims {
            iss: "tenant:acme".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "".into(),
            tenant_id: None,
        };

        let scopes = claims.parse_scopes();
        assert_eq!(scopes.len(), 0);
    }

    #[test]
    fn test_validate_algorithm_rejects_symmetric() {
        let accepted = vec!["EdDSA".to_string(), "RS256".to_string()];

        assert!(validate_algorithm("HS256", &accepted).is_err());
        assert!(validate_algorithm("HS384", &accepted).is_err());
        assert!(validate_algorithm("HS512", &accepted).is_err());
        assert!(validate_algorithm("none", &accepted).is_err());
    }

    #[test]
    fn test_validate_algorithm_accepts_asymmetric() {
        let accepted = vec!["EdDSA".to_string(), "RS256".to_string()];

        assert!(validate_algorithm("EdDSA", &accepted).is_ok());
        assert!(validate_algorithm("RS256", &accepted).is_ok());
    }

    #[test]
    fn test_validate_algorithm_rejects_unlisted() {
        let accepted = vec!["EdDSA".to_string()];

        assert!(validate_algorithm("RS256", &accepted).is_err());
        assert!(validate_algorithm("ES256", &accepted).is_err());
    }

    #[test]
    fn test_decode_jwt_header_malformed() {
        let result = decode_jwt_header("not.a.jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_claims_malformed_parts() {
        let result = decode_jwt_claims("only.two");
        assert!(result.is_err());

        let result = decode_jwt_claims("too.many.parts.here");
        assert!(result.is_err());
    }
}
