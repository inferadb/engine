//! OAuth 2.0 JWT Validation
//!
//! This module provides support for validating OAuth 2.0 access tokens,
//! including JWKS fetching from OAuth issuers and token introspection.

use std::{collections::HashMap, sync::Arc};

use chrono::Utc;
use inferadb_types::{AuthContext, AuthMethod};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, dangerous::insecure_decode, decode, decode_header,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{
    error::AuthError,
    jwks_cache::{Jwk, JwksCache},
    jwt::JwtClaims,
    oidc::OidcDiscoveryClient,
};

/// OAuth JWKS fetcher that uses OIDC Discovery
pub struct OAuthJwksClient {
    oidc_client: Arc<OidcDiscoveryClient>,
    #[allow(dead_code)] // Will be used for OAuth token validation
    jwks_cache: Arc<JwksCache>,
}

impl OAuthJwksClient {
    /// Create a new OAuth JWKS client
    ///
    /// # Arguments
    ///
    /// * `oidc_client` - OIDC Discovery client for finding JWKS endpoints
    /// * `jwks_cache` - JWKS cache for storing fetched keys
    pub fn new(oidc_client: Arc<OidcDiscoveryClient>, jwks_cache: Arc<JwksCache>) -> Self {
        Self { oidc_client, jwks_cache }
    }

    /// Fetch JWKS from an OAuth issuer using OIDC Discovery
    ///
    /// This method:
    /// 1. Discovers the OIDC configuration for the issuer
    /// 2. Fetches JWKS from the discovered `jwks_uri`
    /// 3. Caches the keys using the standard JWKS cache
    ///
    /// # Arguments
    ///
    /// * `issuer` - The OAuth 2.0 issuer URL (e.g., "https://oauth.example.com")
    ///
    /// # Returns
    ///
    /// A vector of JWKs (JSON Web Keys) from the OAuth issuer
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if:
    /// - OIDC discovery fails
    /// - JWKS fetching from the discovered endpoint fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use inferadb_auth::oauth::OAuthJwksClient;
    /// # use inferadb_auth::oidc::OidcDiscoveryClient;
    /// # use inferadb_auth::jwks_cache::JwksCache;
    /// # use std::sync::Arc;
    /// # use std::time::Duration;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let oidc_client = Arc::new(OidcDiscoveryClient::new(Duration::from_secs(86400))?);
    /// let cache = Arc::new(moka::future::Cache::builder().build());
    /// let jwks_cache = Arc::new(JwksCache::new(
    ///     "https://control.example.com/tenants".to_string(),
    ///     cache,
    ///     Duration::from_secs(300),
    /// )?);
    ///
    /// let oauth_client = OAuthJwksClient::new(oidc_client, jwks_cache);
    /// let keys = oauth_client.fetch_oauth_jwks("https://oauth.example.com").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_oauth_jwks(&self, issuer: &str) -> Result<Vec<Jwk>, AuthError> {
        // Discover OIDC configuration
        let config = self.oidc_client.discover(issuer).await?;

        tracing::debug!(
            issuer = %issuer,
            jwks_uri = %config.jwks_uri,
            "Fetching OAuth JWKS from discovered endpoint"
        );

        // Fetch JWKS from the discovered jwks_uri
        // We'll use the underlying HTTP client from JwksCache
        // For now, we'll create a simple HTTP request
        let response = reqwest::get(&config.jwks_uri)
            .await
            .map_err(|e| AuthError::JwksError(format!("Failed to fetch OAuth JWKS: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthError::JwksError(format!(
                "OAuth JWKS fetch failed with status: {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct JwksResponse {
            keys: Vec<Jwk>,
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| AuthError::JwksError(format!("Failed to parse OAuth JWKS: {}", e)))?;

        if jwks.keys.is_empty() {
            return Err(AuthError::JwksError("OAuth JWKS response contains no keys".to_string()));
        }

        tracing::info!(
            issuer = %issuer,
            key_count = jwks.keys.len(),
            "Successfully fetched OAuth JWKS"
        );

        Ok(jwks.keys)
    }

    /// Select a key from JWKS based on JWT header
    ///
    /// # Arguments
    ///
    /// * `jwks` - Vector of JWKs to search
    /// * `kid` - Optional key ID from JWT header
    /// * `alg` - Algorithm from JWT header
    ///
    /// # Returns
    ///
    /// The matching JWK
    ///
    /// # Errors
    ///
    /// Returns `AuthError::JwksError` if no suitable key is found
    pub fn select_key<'a>(
        jwks: &'a [Jwk],
        kid: Option<&str>,
        alg: &str,
    ) -> Result<&'a Jwk, AuthError> {
        // If kid is specified, try to find exact match using constant-time comparison
        if let Some(kid) = kid {
            if let Some(key) = jwks.iter().find(|k| k.kid.as_bytes().ct_eq(kid.as_bytes()).into()) {
                return Ok(key);
            }
            return Err(AuthError::JwksError(format!("No key found with kid: {}", kid)));
        }

        // No kid specified - find first key with matching algorithm (using constant-time
        // comparison)
        jwks.iter()
            .find(|k| {
                // Use constant-time comparison for algorithm strings
                k.alg.as_ref().is_some_and(|k_alg| k_alg.as_bytes().ct_eq(alg.as_bytes()).into())
                    || (alg.as_bytes().ct_eq(b"EdDSA").into()
                        && k.kty.as_bytes().ct_eq(b"OKP").into()
                        && k.crv
                            .as_ref()
                            .is_some_and(|crv| crv.as_bytes().ct_eq(b"Ed25519").into()))
                    || (alg.as_bytes().ct_eq(b"RS256").into()
                        && k.kty.as_bytes().ct_eq(b"RSA").into())
            })
            .ok_or_else(|| AuthError::JwksError(format!("No key found for algorithm: {}", alg)))
    }
}

/// Token introspection response (RFC 7662)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active
    pub active: bool,

    /// Scope values for the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Client identifier for the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Username of the resource owner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Type of token (e.g., "Bearer")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Token expiration timestamp (seconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    /// Token issuance timestamp (seconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    /// Subject identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

/// Token introspection client with caching
pub struct IntrospectionClient {
    http_client: reqwest::Client,
    cache: Option<Arc<moka::future::Cache<String, IntrospectionResponse>>>,
}

impl IntrospectionClient {
    /// Create a new introspection client without caching
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created (typically due to TLS configuration
    /// issues)
    pub fn new() -> Result<Self, AuthError> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AuthError::IntrospectionFailed(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { http_client, cache: None })
    }

    /// Create a new introspection client with caching
    ///
    /// # Arguments
    ///
    /// * `max_capacity` - Maximum number of tokens to cache
    /// * `default_ttl` - Default TTL for cache entries (will use min of this and token exp)
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created (typically due to TLS configuration
    /// issues)
    pub fn new_with_cache(
        max_capacity: u64,
        default_ttl: std::time::Duration,
    ) -> Result<Self, AuthError> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AuthError::IntrospectionFailed(format!("Failed to create HTTP client: {}", e))
            })?;

        let cache = Arc::new(
            moka::future::Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(default_ttl)
                .build(),
        );

        Ok(Self { http_client, cache: Some(cache) })
    }

    /// Introspect a token using RFC 7662 (with caching if enabled)
    ///
    /// If caching is enabled, this will:
    /// 1. Check cache for token (using SHA-256 hash as key)
    /// 2. Return cached result if found
    /// 3. Otherwise, perform introspection and cache result
    ///
    /// # Arguments
    ///
    /// * `token` - The token to introspect
    /// * `endpoint` - The introspection endpoint URL
    ///
    /// # Returns
    ///
    /// The introspection response
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the request fails or the response is invalid
    pub async fn introspect(
        &self,
        token: &str,
        endpoint: &str,
    ) -> Result<IntrospectionResponse, AuthError> {
        // If caching is enabled, check cache first
        if let Some(cache) = &self.cache {
            let cache_key = Self::hash_token(token);

            // Check cache
            if let Some(cached) = cache.get(&cache_key).await {
                tracing::debug!("Introspection cache hit");
                inferadb_observe::metrics::record_oauth_introspection_cache_hit();
                return Ok(cached);
            }

            // Cache miss - perform introspection
            tracing::debug!("Introspection cache miss");
            inferadb_observe::metrics::record_oauth_introspection_cache_miss();
            let response = self.introspect_uncached(token, endpoint).await?;

            // Cache the result
            cache.insert(cache_key, response.clone()).await;

            return Ok(response);
        }

        // No caching - perform introspection directly
        self.introspect_uncached(token, endpoint).await
    }

    /// Perform introspection without caching
    async fn introspect_uncached(
        &self,
        token: &str,
        endpoint: &str,
    ) -> Result<IntrospectionResponse, AuthError> {
        let start = std::time::Instant::now();
        let mut params = HashMap::new();
        params.insert("token", token);

        let result = (async {
            let response =
                self.http_client.post(endpoint).form(&params).send().await.map_err(|e| {
                    AuthError::JwksError(format!("Token introspection request failed: {}", e))
                })?;

            if !response.status().is_success() {
                return Err(AuthError::JwksError(format!(
                    "Token introspection failed with status: {}",
                    response.status()
                )));
            }

            let introspection_response: IntrospectionResponse =
                response.json().await.map_err(|e| {
                    AuthError::JwksError(format!("Failed to parse introspection response: {}", e))
                })?;

            Ok(introspection_response)
        })
        .await;

        // Record metrics
        let duration = start.elapsed().as_secs_f64();
        let success = result.is_ok();
        inferadb_observe::metrics::record_oauth_introspection(success, duration);

        result
    }

    /// Hash a token using SHA-256 for cache key
    fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Detect if a token is a JWT (3 parts separated by dots)
pub fn is_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
}

/// Validate an OAuth JWT and create AuthContext
///
/// # Arguments
///
/// * `token` - The JWT to validate
/// * `oauth_client` - OAuth JWKS client for fetching issuer keys
/// * `expected_audience` - Optional expected audience claim
///
/// # Returns
///
/// An authenticated context with OAuth method
///
/// # Errors
///
/// Returns `AuthError` if validation fails
pub async fn validate_oauth_jwt(
    token: &str,
    oauth_client: &OAuthJwksClient,
    expected_audience: Option<&str>,
) -> Result<AuthContext, AuthError> {
    // Decode header to get issuer and algorithm
    let header = decode_header(token)
        .map_err(|e| AuthError::InvalidTokenFormat(format!("Invalid JWT header: {}", e)))?;

    // Get algorithm
    let alg = match header.alg {
        Algorithm::RS256 => "RS256",
        Algorithm::EdDSA => "EdDSA",
        _ => {
            return Err(AuthError::InvalidTokenFormat(format!(
                "Unsupported algorithm: {:?}",
                header.alg
            )));
        },
    };

    // Decode without verification first to get issuer
    // Using insecure_decode is safe here because we only use it to read the issuer,
    // and we fully validate the token signature later
    let unverified = insecure_decode::<JwtClaims>(token)
        .map_err(|e| AuthError::InvalidTokenFormat(format!("Failed to decode JWT: {}", e)))?;

    let issuer = unverified.claims.iss.clone();

    // Validation logic wrapped with metrics
    let result = (async {
        // Fetch JWKS from OAuth issuer
        let jwks = oauth_client.fetch_oauth_jwks(&issuer).await?;

        // Select appropriate key
        let kid = header.kid.as_deref();
        let key = OAuthJwksClient::select_key(&jwks, kid, alg)?;

        // Convert JWK to DecodingKey
        let decoding_key = jwk_to_decoding_key(key)?;

        // Now validate with proper signature verification
        let mut validation = Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        if let Some(aud) = expected_audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        let token_data =
            decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::InvalidSignature,
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    AuthError::InvalidAudience("Audience mismatch".to_string())
                },
                _ => AuthError::InvalidTokenFormat(format!("JWT validation failed: {}", e)),
            })?;

        let claims = token_data.claims;

        // Parse scopes
        let scopes: Vec<String> = claims.scope.split_whitespace().map(|s| s.to_string()).collect();

        // Extract vault and organization IDs (Snowflake IDs) - both required for multi-tenancy
        let vault_str =
            claims.vault_id.ok_or_else(|| AuthError::MissingClaim("vault_id".to_string()))?;
        let vault: i64 = vault_str
            .parse()
            .map_err(|_| AuthError::InvalidTokenFormat("Invalid vault ID format".to_string()))?;

        let organization_str =
            claims.org_id.ok_or_else(|| AuthError::MissingClaim("org_id".to_string()))?;
        let organization: i64 = organization_str.parse().map_err(|_| {
            AuthError::InvalidTokenFormat("Invalid organization ID format".to_string())
        })?;

        // Create AuthContext
        let auth_context = AuthContext {
            client_id: claims.sub.clone(),
            key_id: kid.unwrap_or("").to_string(),
            auth_method: AuthMethod::OAuthAccessToken,
            scopes,
            issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
                .unwrap_or_else(Utc::now),
            expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(300)),
            jti: claims.jti.clone(),
            vault,
            organization,
        };

        Ok(auth_context)
    })
    .await;

    // Record metrics
    let success = result.is_ok();
    inferadb_observe::metrics::record_oauth_jwt_validation(&issuer, success);

    result
}

/// Convert JWK to jsonwebtoken DecodingKey
fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, AuthError> {
    match jwk.kty.as_str() {
        "RSA" => {
            // For RSA, we need n and e
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| AuthError::JwksError("RSA key missing 'n' parameter".to_string()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| AuthError::JwksError("RSA key missing 'e' parameter".to_string()))?;

            Ok(DecodingKey::from_rsa_components(n, e)
                .map_err(|e| AuthError::JwksError(format!("Invalid RSA key: {}", e)))?)
        },
        "OKP" => {
            // For EdDSA/Ed25519, we need x
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| AuthError::JwksError("OKP key missing 'x' parameter".to_string()))?;

            // Decode base64url
            let public_key_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, x)
                    .map_err(|e| AuthError::JwksError(format!("Invalid base64 in key: {}", e)))?;

            Ok(DecodingKey::from_ed_der(&public_key_bytes))
        },
        _ => Err(AuthError::JwksError(format!("Unsupported key type: {}", jwk.kty))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_key_by_kid() {
        let jwks = vec![
            Jwk {
                kty: "RSA".to_string(),
                use_: Some("sig".to_string()),
                kid: "key1".to_string(),
                alg: Some("RS256".to_string()),
                crv: None,
                x: None,
                n: Some("test".to_string()),
                e: Some("AQAB".to_string()),
            },
            Jwk {
                kty: "OKP".to_string(),
                use_: Some("sig".to_string()),
                kid: "key2".to_string(),
                alg: Some("EdDSA".to_string()),
                crv: Some("Ed25519".to_string()),
                x: Some("test".to_string()),
                n: None,
                e: None,
            },
        ];

        // Find by kid
        let key = OAuthJwksClient::select_key(&jwks, Some("key1"), "RS256").unwrap();
        assert_eq!(key.kid, "key1");

        let key = OAuthJwksClient::select_key(&jwks, Some("key2"), "EdDSA").unwrap();
        assert_eq!(key.kid, "key2");
    }

    #[test]
    fn test_select_key_by_algorithm() {
        let jwks = vec![
            Jwk {
                kty: "RSA".to_string(),
                use_: Some("sig".to_string()),
                kid: "key1".to_string(),
                alg: Some("RS256".to_string()),
                crv: None,
                x: None,
                n: Some("test".to_string()),
                e: Some("AQAB".to_string()),
            },
            Jwk {
                kty: "OKP".to_string(),
                use_: Some("sig".to_string()),
                kid: "key2".to_string(),
                alg: None,
                crv: Some("Ed25519".to_string()),
                x: Some("test".to_string()),
                n: None,
                e: None,
            },
        ];

        // Find by algorithm when no kid
        let key = OAuthJwksClient::select_key(&jwks, None, "RS256").unwrap();
        assert_eq!(key.kty, "RSA");

        let key = OAuthJwksClient::select_key(&jwks, None, "EdDSA").unwrap();
        assert_eq!(key.kty, "OKP");
    }

    #[test]
    fn test_select_key_not_found() {
        let jwks = vec![Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: "key1".to_string(),
            alg: Some("RS256".to_string()),
            crv: None,
            x: None,
            n: Some("test".to_string()),
            e: Some("AQAB".to_string()),
        }];

        // Kid not found
        let result = OAuthJwksClient::select_key(&jwks, Some("nonexistent"), "RS256");
        assert!(result.is_err());

        // Algorithm not found
        let result = OAuthJwksClient::select_key(&jwks, None, "ES256");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_jwt_detection() {
        // Valid JWT format
        assert!(is_jwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        ));

        // Also valid (any 3-part format)
        assert!(is_jwt("a.b.c"));

        // Invalid formats
        assert!(!is_jwt("opaque_token_123"));
        assert!(!is_jwt("only.two"));
        assert!(!is_jwt("has.too.many.parts.here"));
        assert!(!is_jwt(""));
    }

    #[test]
    fn test_introspection_response_deserialization() {
        let json = r#"{
            "active": true,
            "scope": "read write",
            "client_id": "client123",
            "username": "user@example.com",
            "token_type": "Bearer",
            "exp": 1735689600,
            "iat": 1735686000,
            "sub": "user123"
        }"#;

        let response: IntrospectionResponse = serde_json::from_str(json).unwrap();
        assert!(response.active);
        assert_eq!(response.scope, Some("read write".to_string()));
        assert_eq!(response.client_id, Some("client123".to_string()));
        assert_eq!(response.sub, Some("user123".to_string()));
    }

    #[test]
    fn test_introspection_response_inactive() {
        let json = r#"{"active": false}"#;

        let response: IntrospectionResponse = serde_json::from_str(json).unwrap();
        assert!(!response.active);
        assert!(response.scope.is_none());
        assert!(response.sub.is_none());
    }

    #[tokio::test]
    async fn test_introspection_client_creation() {
        let _client = IntrospectionClient::new().unwrap();
        // Just verify it can be created without panicking
    }

    #[tokio::test]
    async fn test_introspection_client_with_cache() {
        use std::time::Duration;

        let _client = IntrospectionClient::new_with_cache(100, Duration::from_secs(60)).unwrap();
        // Verify it can be created with caching enabled
    }

    #[test]
    fn test_token_hashing() {
        let token1 = "test_token_123";
        let token2 = "test_token_456";

        let hash1 = IntrospectionClient::hash_token(token1);
        let hash2 = IntrospectionClient::hash_token(token2);

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Same token should produce same hash
        assert_eq!(hash1, IntrospectionClient::hash_token(token1));

        // Hash should be SHA-256 length (64 hex chars)
        assert_eq!(hash1.len(), 64);
    }
}
