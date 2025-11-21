use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{error::AuthError, validation::validate_algorithm};

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
    /// Vault ID (Snowflake ID for multi-tenancy isolation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Account ID (Snowflake ID of vault owner)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

impl JwtClaims {
    /// Extract tenant ID from claims
    /// For tenant JWTs: parse from "tenant:acme" format in iss
    /// For OAuth tokens: use tenant_id claim
    /// For Management API client JWTs: use account claim (organization/account ID)
    pub fn extract_tenant_id(&self) -> Result<String, AuthError> {
        // First check explicit tenant_id claim (OAuth tokens)
        if let Some(ref tenant_id) = self.tenant_id {
            if !tenant_id.is_empty() {
                return Ok(tenant_id.clone());
            }
        }

        // Check account claim (Management API client JWTs)
        // The account claim contains the organization/account ID
        if let Some(ref account) = self.account {
            if !account.is_empty() {
                return Ok(account.clone());
            }
        }

        // Fall back to parsing from issuer (tenant JWTs)
        if let Some(tenant) = self.iss.strip_prefix("tenant:") {
            if !tenant.is_empty() {
                return Ok(tenant.to_string());
            }
        }

        Err(AuthError::MissingClaim(
            "tenant_id (could not extract from iss, tenant_id, or account claim)".into(),
        ))
    }

    /// Parse scopes from space-separated string
    pub fn parse_scopes(&self) -> Vec<String> {
        self.scope.split_whitespace().map(|s| s.to_string()).collect()
    }

    /// Extract vault ID (Snowflake ID) from claims
    /// Returns None if not present
    pub fn extract_vault(&self) -> Option<String> {
        self.vault.clone()
    }

    /// Extract account ID (Snowflake ID) from claims
    /// Returns None if not present
    pub fn extract_account(&self) -> Option<String> {
        self.account.clone()
    }
}

/// Decode JWT header without verification
pub fn decode_jwt_header(token: &str) -> Result<Header, AuthError> {
    decode_header(token)
        .map_err(|e| AuthError::InvalidTokenFormat(format!("Failed to decode JWT header: {}", e)))
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
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| {
        AuthError::InvalidTokenFormat(format!("Failed to decode JWT payload: {}", e))
    })?;

    // Parse as JSON
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AuthError::InvalidTokenFormat(format!("Failed to parse JWT claims: {}", e)))?;

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
pub fn validate_claims(
    claims: &JwtClaims,
    expected_audience: Option<&str>,
) -> Result<(), AuthError> {
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
        return Err(AuthError::InvalidTokenFormat("iat claim is in the future".into()));
    }
    if now - claims.iat > 86400 {
        // 24 hours
        return Err(AuthError::InvalidTokenFormat("iat claim is too old (> 24 hours)".into()));
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

/// Verify JWT signature with a public key
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

/// Verify JWT signature using JWKS cache
///
/// This is the primary JWT verification function that:
/// 1. Decodes the JWT header to extract the key ID (`kid`) and algorithm
/// 2. Extracts the tenant ID from the JWT claims
/// 3. Fetches the corresponding public key from the JWKS cache
/// 4. Verifies the JWT signature using the public key
///
/// The JWKS cache handles key fetching, caching, and rotation automatically.
///
/// # Arguments
///
/// * `token` - The JWT token to verify (as a string)
/// * `jwks_cache` - The JWKS cache instance
///
/// # Returns
///
/// Returns the validated JWT claims if verification succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - The JWT is malformed or missing required fields (`kid`, tenant ID)
/// - The algorithm is not supported (only EdDSA and RS256 are allowed)
/// - The key cannot be found in JWKS (even after refresh)
/// - The signature is invalid
///
/// # Example
///
/// ```no_run
/// use infera_auth::jwt::verify_with_jwks;
/// use infera_auth::jwks_cache::JwksCache;
/// use moka::future::Cache;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Setup JWKS cache
/// let cache = Arc::new(Cache::new(100));
/// let jwks_cache = JwksCache::new(
///     "https://control-plane.example.com".to_string(),
///     cache,
///     Duration::from_secs(300),
/// )?;
///
/// // Verify a JWT
/// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImFjbWUta2V5LTAwMSJ9...";
/// let claims = verify_with_jwks(token, &jwks_cache).await?;
///
/// println!("Verified claims for tenant: {}", claims.iss);
/// # Ok(())
/// # }
/// ```
pub async fn verify_with_jwks(
    token: &str,
    jwks_cache: &crate::jwks_cache::JwksCache,
) -> Result<JwtClaims, AuthError> {
    // 1. Decode header to get algorithm and key ID
    let header = decode_jwt_header(token)?;

    let kid = header
        .kid
        .ok_or_else(|| AuthError::InvalidTokenFormat("JWT header missing 'kid' field".into()))?;

    // Validate algorithm
    let alg_str = format!("{:?}", header.alg);
    validate_algorithm(&alg_str, &["EdDSA".to_string(), "RS256".to_string()])?;

    // 2. Decode claims without verification to extract tenant ID
    let claims = decode_jwt_claims(token)?;
    let tenant_id = claims.extract_tenant_id()?;

    // 3. Get key from JWKS cache
    let jwk = match jwks_cache.get_key_by_id(&tenant_id, &kid).await {
        Ok(key) => key,
        Err(_) => {
            // Key not found - retry with fresh JWKS fetch
            tracing::info!(
                tenant_id = %tenant_id,
                kid = %kid,
                "Key not found in JWKS, forcing refresh"
            );

            // Force a fresh fetch by getting all keys
            let keys = jwks_cache.get_jwks(&tenant_id).await?;

            // Try to find the key again (using constant-time comparison)
            keys.into_iter().find(|k| k.kid.as_bytes().ct_eq(kid.as_bytes()).into()).ok_or_else(
                || {
                    AuthError::JwksError(format!(
                        "Key '{}' not found in JWKS for tenant '{}'",
                        kid, tenant_id
                    ))
                },
            )?
        },
    };

    // 4. Convert JWK to DecodingKey
    let decoding_key = jwk.to_decoding_key()?;

    // 5. Verify signature
    let verified_claims = verify_signature(token, &decoding_key, header.alg)?;

    Ok(verified_claims)
}

/// Verify JWT signature using certificate cache with fallback to JWKS
///
/// This function provides a hybrid verification approach:
/// 1. First, checks if the `kid` matches the Management API format
///    (org-{org_id}-client-{client_id}-cert-{cert_id})
/// 2. If it matches, attempts to fetch the certificate from the Management API via the certificate
///    cache
/// 3. If the `kid` doesn't match or certificate fetch fails, falls back to JWKS verification
///
/// This allows the system to support both Management API client certificates and traditional JWKS
/// keys.
///
/// # Arguments
///
/// * `token` - The JWT token to verify (as a string)
/// * `cert_cache` - Optional certificate cache for Management API certificates
/// * `jwks_cache` - The JWKS cache instance (used as fallback)
///
/// # Returns
///
/// Returns the validated JWT claims if verification succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - The JWT is malformed or missing required fields (`kid`, tenant ID)
/// - The algorithm is not supported (only EdDSA and RS256 are allowed)
/// - Neither certificate cache nor JWKS can verify the token
/// - The signature is invalid
///
/// # Example
///
/// ```no_run
/// use infera_auth::jwt::verify_with_cert_cache_or_jwks;
/// use infera_auth::certificate_cache::CertificateCache;
/// use infera_auth::jwks_cache::JwksCache;
/// use moka::future::Cache;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Setup certificate cache (fetches from Management API JWKS endpoint)
/// let cert_cache = CertificateCache::new(
///     "https://management-api.inferadb.com".to_string(),
///     Duration::from_secs(300),
///     100,
/// )?;
///
/// // Setup JWKS cache (for OIDC providers)
/// let cache = Arc::new(Cache::new(100));
/// let jwks_cache = JwksCache::new(
///     "https://auth.inferadb.com/.well-known".to_string(),
///     cache,
///     Duration::from_secs(300),
/// )?;
///
/// // Verify a JWT (will try cert cache first, then JWKS)
/// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6Im9yZy0uLi4ifQ...";
/// let claims = verify_with_cert_cache_or_jwks(token, Some(&cert_cache), &jwks_cache).await?;
///
/// println!("Verified claims for tenant: {}", claims.iss);
/// # Ok(())
/// # }
/// ```
pub async fn verify_with_cert_cache_or_jwks(
    token: &str,
    cert_cache: Option<&crate::certificate_cache::CertificateCache>,
    jwks_cache: &crate::jwks_cache::JwksCache,
) -> Result<JwtClaims, AuthError> {
    // 1. Decode header to get algorithm and key ID
    let header = decode_jwt_header(token)?;

    let kid = header
        .kid
        .ok_or_else(|| AuthError::InvalidTokenFormat("JWT header missing 'kid' field".into()))?;

    // Validate algorithm
    let alg_str = format!("{:?}", header.alg);
    validate_algorithm(&alg_str, &["EdDSA".to_string(), "RS256".to_string()])?;

    // 2. Try certificate cache first if available and kid matches format
    if let Some(cache) = cert_cache {
        // Check if kid matches Management API format
        // (org-{org_id}-client-{client_id}-cert-{cert_id})
        if kid.starts_with("org-") && kid.contains("-client-") && kid.contains("-cert-") {
            match cache.get_decoding_key(&kid).await {
                Ok(decoding_key) => {
                    tracing::debug!(
                        kid = %kid,
                        "Successfully fetched certificate from Management API"
                    );

                    // Verify signature with Management API certificate
                    let verified_claims = verify_signature(token, &decoding_key, header.alg)?;
                    return Ok(verified_claims);
                },
                Err(e) => {
                    // Log the error but continue to JWKS fallback
                    tracing::warn!(
                        kid = %kid,
                        error = %e,
                        "Failed to fetch certificate from Management API, falling back to JWKS"
                    );
                },
            }
        }
    }

    // 3. Fall back to JWKS verification
    tracing::debug!(
        kid = %kid,
        "Using JWKS verification"
    );
    verify_with_jwks(token, jwks_cache).await
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
            vault: None,
            account: None,
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
            vault: None,
            account: None,
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
            vault: None,
            account: None,
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
            vault: None,
            account: None,
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
            vault: None,
            account: None,
        };

        let scopes = claims.parse_scopes();
        assert_eq!(scopes.len(), 0);
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
