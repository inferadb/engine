use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

use crate::{error::AuthError, validation::validate_algorithm};

/// JWT claims structure
///
/// Per the Management API specification, JWTs should have the following structure:
///
/// ```json
/// {
///   "iss": "https://api.inferadb.com",
///   "sub": "client:<client_id>",
///   "aud": "https://api.inferadb.com/evaluate",
///   "exp": 1234567890,
///   "iat": 1234567800,
///   "org_id": "<organization_id>",
///   "vault_id": "<vault_id>",
///   "vault_role": "write",
///   "scope": "vault:read vault:write"
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer - Should be the Management API URL (e.g., "https://api.inferadb.com")
    pub iss: String,
    /// Subject - Client identifier (e.g., "client:<client_id>")
    pub sub: String,
    /// Audience - Target service (e.g., "https://api.inferadb.com/evaluate")
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
    /// Space-separated scopes (e.g., "vault:read vault:write")
    pub scope: String,
    /// Vault ID (Snowflake ID as string for multi-tenancy isolation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    /// Organization ID (Snowflake ID as string - primary identifier per Management API spec)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

impl JwtClaims {
    /// Extract organization ID from claims
    ///
    /// Per the Management API specification, the organization ID is stored in the `org_id` claim.
    ///
    /// # Returns
    ///
    /// The organization ID as a string
    ///
    /// # Errors
    ///
    /// Returns `AuthError::MissingClaim` if the `org_id` claim is missing or empty
    pub fn extract_org_id(&self) -> Result<String, AuthError> {
        // Extract org_id claim (Management API client JWTs - per spec)
        // The org_id claim contains the organization ID (Snowflake ID as string)
        if let Some(ref org_id) = self.org_id
            && !org_id.is_empty()
        {
            return Ok(org_id.clone());
        }

        Err(AuthError::MissingClaim("org_id".into()))
    }

    /// Parse scopes from space-separated string
    pub fn parse_scopes(&self) -> Vec<String> {
        self.scope.split_whitespace().map(|s| s.to_string()).collect()
    }

    /// Extract vault ID (Snowflake ID) from claims
    /// Returns None if not present
    pub fn extract_vault_id(&self) -> Option<String> {
        self.vault_id.clone()
    }

    /// Extract organization ID (Snowflake ID) from claims
    /// Returns None if not present
    pub fn extract_organization(&self) -> Option<String> {
        self.org_id.clone()
    }
}

/// Decode JWT header without verification
pub fn decode_jwt_header(token: &str) -> Result<Header, AuthError> {
    decode_header(token)
        .map_err(|e| AuthError::InvalidTokenFormat(format!("Failed to decode JWT header: {}", e)))
}

/// Decode JWT claims without verification (used to extract issuer for key lookup)
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
    if let Some(nbf) = claims.nbf
        && nbf > now
    {
        return Err(AuthError::TokenNotYetValid);
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
    if let Some(expected) = expected_audience
        && claims.aud != expected
    {
        return Err(AuthError::InvalidAudience(format!(
            "expected '{}', got '{}'",
            expected, claims.aud
        )));
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
    validation.validate_exp = true; // Validate token expiration
    validation.validate_nbf = false;
    validation.validate_aud = false;

    let token_data = decode::<JwtClaims>(token, key, &validation)?;

    Ok(token_data.claims)
}

/// Verify JWT signature using Ledger-backed signing key cache
///
/// This function verifies JWTs using public signing keys fetched from Ledger:
/// 1. Decodes the JWT header to extract the key ID (`kid`) and algorithm
/// 2. Extracts the organization ID from the JWT claims
/// 3. Fetches the corresponding public key from the signing key cache (backed by Ledger)
/// 4. Verifies the JWT signature using the public key
///
/// This approach eliminates the need for JWKS endpoints and Control connectivity,
/// as signing keys are stored directly in Ledger.
///
/// # Arguments
///
/// * `token` - The JWT token to verify (as a string)
/// * `signing_key_cache` - The Ledger-backed signing key cache
///
/// # Returns
///
/// Returns the validated JWT claims if verification succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - The JWT is malformed or missing required fields (`kid`, `org_id`)
/// - The algorithm is not supported (only EdDSA is allowed for Ledger keys)
/// - The key cannot be found in Ledger or is inactive/revoked/expired
/// - The signature is invalid
///
/// # Example
///
/// ```no_run
/// use inferadb_engine_auth::jwt::verify_with_signing_key_cache;
/// use inferadb_engine_auth::signing_key_cache::SigningKeyCache;
/// use inferadb_storage::auth::MemorySigningKeyStore;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Setup signing key cache backed by Ledger
/// let store = Arc::new(MemorySigningKeyStore::new());
/// let cache = SigningKeyCache::new(store, Duration::from_secs(300));
///
/// // Verify a JWT using Ledger keys
/// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6Im9yZy0uLi4ifQ...";
/// let claims = verify_with_signing_key_cache(token, &cache).await?;
///
/// println!("Verified claims for organization: {}", claims.org_id.unwrap_or_default());
/// # Ok(())
/// # }
/// ```
pub async fn verify_with_signing_key_cache(
    token: &str,
    signing_key_cache: &crate::signing_key_cache::SigningKeyCache,
) -> Result<JwtClaims, AuthError> {
    // 1. Decode header to get algorithm and key ID
    let header = decode_jwt_header(token)?;

    let kid = header
        .kid
        .ok_or_else(|| AuthError::InvalidTokenFormat("JWT header missing 'kid' field".into()))?;

    // Validate algorithm (only EdDSA for Ledger keys)
    let alg_str = format!("{:?}", header.alg);
    validate_algorithm(&alg_str)?;

    // EdDSA is required for Ledger-backed keys
    if header.alg != Algorithm::EdDSA {
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Ledger-backed keys only support EdDSA, got {:?}",
            header.alg
        )));
    }

    // 2. Decode claims without verification to extract organization ID
    let claims = decode_jwt_claims(token)?;
    let org_id_str = claims.extract_org_id()?;
    let org_id: i64 = org_id_str.parse().map_err(|_| {
        AuthError::InvalidTokenFormat(format!(
            "org_id '{}' is not a valid Snowflake ID",
            org_id_str
        ))
    })?;

    // 3. Get decoding key from signing key cache (fetches from Ledger on cache miss)
    let decoding_key = signing_key_cache.get_decoding_key(org_id, &kid).await.map_err(|e| {
        tracing::warn!(
            org_id = %org_id,
            kid = %kid,
            error = %e,
            "Failed to get signing key from Ledger"
        );
        // Convert signing key cache errors to appropriate auth errors
        e
    })?;

    // 4. Verify signature with the Ledger-backed key
    let verified_claims = verify_signature(token, &decoding_key, header.alg)?;

    tracing::debug!(
        org_id = %org_id,
        kid = %kid,
        "JWT verified using Ledger-backed signing key"
    );

    Ok(verified_claims)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_org_id_from_org_id_claim() {
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "vault:read vault:write".into(),
            vault_id: Some("123456789".into()),
            org_id: Some("987654321".into()),
        };

        assert_eq!(claims.extract_org_id().unwrap(), "987654321");
    }

    #[test]
    fn test_extract_org_id_missing() {
        let claims = JwtClaims {
            iss: "https://auth.example.com".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check".into(),
            vault_id: None,
            org_id: None,
        };

        assert!(claims.extract_org_id().is_err());
    }

    #[test]
    fn test_extract_org_id_empty() {
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "vault:read vault:write".into(),
            vault_id: Some("123456789".into()),
            org_id: Some("".into()),
        };

        assert!(claims.extract_org_id().is_err());
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
            vault_id: None,
            org_id: None,
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
            vault_id: None,
            org_id: None,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ledger_verification_tests {
    use std::{sync::Arc, time::Duration};

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use inferadb_storage::auth::{MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rand_core::OsRng;

    use super::*;
    use crate::signing_key_cache::SigningKeyCache;

    /// Generate a test Ed25519 key pair and return (pkcs8_der, public_key_base64)
    fn generate_test_keypair() -> (Vec<u8>, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes);

        // Create PKCS#8 DER encoding for Ed25519 private key
        let private_bytes = signing_key.to_bytes();
        let mut pkcs8_der = vec![
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER version 0
            0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x04, 0x22, // OCTET STRING, 34 bytes
            0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
        ];
        pkcs8_der.extend_from_slice(&private_bytes);

        (pkcs8_der, public_key_b64)
    }

    /// Create a JWT signed with the given PKCS#8 DER key
    fn create_test_jwt(pkcs8_der: &[u8], kid: &str, org_id: &str) -> String {
        let now = Utc::now().timestamp() as u64;
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            jti: Some("test-jti-12345".into()),
            scope: "vault:read vault:write".into(),
            vault_id: Some("123456789".into()),
            org_id: Some(org_id.into()),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());

        let encoding_key = EncodingKey::from_ed_der(pkcs8_der);
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("Failed to encode test JWT")
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_success() {
        // Generate key pair
        let (pkcs8_der, public_key_b64) = generate_test_keypair();
        let kid = "test-key-001";
        let org_id: i64 = 12345;

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));

        // Register the public key
        let public_key = PublicSigningKey {
            kid: kid.to_string(),
            public_key: public_key_b64,
            client_id: 1,
            cert_id: 1,
            created_at: Utc::now(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            active: true,
            revoked_at: None,
        };
        store.create_key(org_id, &public_key).await.unwrap();

        // Create and verify JWT
        let token = create_test_jwt(&pkcs8_der, kid, &org_id.to_string());
        let claims = verify_with_signing_key_cache(&token, &cache).await.unwrap();

        assert_eq!(claims.org_id, Some(org_id.to_string()));
        assert_eq!(claims.sub, "client:test-client");
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_key_not_found() {
        // Generate key pair
        let (pkcs8_der, _) = generate_test_keypair();
        let kid = "nonexistent-key";
        let org_id: i64 = 12345;

        // Create store and cache (without registering the key)
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(300));

        // Create JWT
        let token = create_test_jwt(&pkcs8_der, kid, &org_id.to_string());
        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::KeyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_key_revoked() {
        // Generate key pair
        let (pkcs8_der, public_key_b64) = generate_test_keypair();
        let kid = "revoked-key";
        let org_id: i64 = 12345;

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));

        // Register a revoked key
        let public_key = PublicSigningKey {
            kid: kid.to_string(),
            public_key: public_key_b64,
            client_id: 1,
            cert_id: 1,
            created_at: Utc::now(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            active: true,
            revoked_at: Some(Utc::now()),
        };
        store.create_key(org_id, &public_key).await.unwrap();

        // Create JWT
        let token = create_test_jwt(&pkcs8_der, kid, &org_id.to_string());
        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::KeyRevoked { .. })));
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_invalid_org_id() {
        // Generate key pair
        let (pkcs8_der, _) = generate_test_keypair();
        let kid = "test-key";

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(300));

        // Create JWT with non-numeric org_id
        let now = Utc::now().timestamp() as u64;
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            jti: None,
            scope: "vault:read".into(),
            vault_id: None,
            org_id: Some("not-a-number".into()),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());

        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::InvalidTokenFormat(_))));
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_missing_kid() {
        // Generate key pair
        let (pkcs8_der, _) = generate_test_keypair();

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(300));

        // Create JWT without kid
        let now = Utc::now().timestamp() as u64;
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            jti: None,
            scope: "vault:read".into(),
            vault_id: None,
            org_id: Some("12345".into()),
        };

        let header = Header::new(Algorithm::EdDSA); // No kid set
        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::InvalidTokenFormat(_))));
    }
}
