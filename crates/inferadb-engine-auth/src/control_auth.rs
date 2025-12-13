//! Control JWT authentication middleware
//!
//! This module provides authentication for requests FROM Control TO the Engine.
//! This is the reverse of the normal flow where the Engine validates client JWTs issued by
//! Control.
//!
//! Control uses this to authenticate when calling Engine internal endpoints
//! (like cache invalidation callbacks).
//!
//! ## Discovery Support
//!
//! When service discovery is enabled (Kubernetes or Tailscale), the cache will:
//! 1. Discover all Control service pod IPs
//! 2. Fetch JWKS from each discovered endpoint
//! 3. Aggregate all keys by `kid` (key ID)
//! 4. Validate JWTs using any key from any Control instance
//!
//! This allows the server to validate JWTs signed by any Control service instance
//! in a distributed deployment.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_engine_config::DiscoveryMode;
use inferadb_engine_discovery::{Endpoint, EndpointDiscovery, EndpointHealth};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{error::AuthError, jwt::decode_jwt_header, middleware::extract_bearer_token};

/// Context attached to requests authenticated by Control
#[derive(Clone, Debug)]
pub struct ControlContext {
    /// Control instance ID (from JWT subject: "management:{control_id}")
    pub control_id: String,
    /// JWT ID for replay protection
    pub jti: Option<String>,
    /// When the token was issued
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// When the token expires
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// JWKS response from Control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlJwks {
    /// List of JWKs
    pub keys: Vec<ControlJwk>,
}

/// JWK from Control JWKS endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlJwk {
    kty: String,
    alg: String,
    /// Key ID - unique identifier for this key
    pub kid: String,
    #[serde(rename = "use")]
    key_use: String,
    // EdDSA key
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    // RSA key
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
}

impl ControlJwk {
    /// Convert JWK to jsonwebtoken DecodingKey
    fn to_decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, AuthError> {
        match self.kty.as_str() {
            "OKP" => {
                // EdDSA key
                let x = self.x.as_ref().ok_or_else(|| {
                    AuthError::JwksError("Missing x parameter for OKP key".into())
                })?;

                let crv = self.crv.as_ref().ok_or_else(|| {
                    AuthError::JwksError("Missing crv parameter for OKP key".into())
                })?;

                if crv != "Ed25519" {
                    return Err(AuthError::JwksError(format!("Unsupported curve: {}", crv)));
                }

                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                let x_bytes = URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| AuthError::JwksError(format!("Invalid base64 in x: {}", e)))?;

                Ok(jsonwebtoken::DecodingKey::from_ed_der(&x_bytes))
            },
            "RSA" => {
                // RSA key
                let n = self.n.as_ref().ok_or_else(|| {
                    AuthError::JwksError("Missing n parameter for RSA key".into())
                })?;
                let e = self.e.as_ref().ok_or_else(|| {
                    AuthError::JwksError("Missing e parameter for RSA key".into())
                })?;

                Ok(jsonwebtoken::DecodingKey::from_rsa_components(n, e)?)
            },
            _ => Err(AuthError::JwksError(format!("Unsupported key type: {}", self.kty))),
        }
    }
}

/// Control JWKS cache
///
/// This cache fetches and caches the Control's public keys from its
/// /.well-known/jwks.json endpoint. These keys are used to verify JWTs signed
/// by the Control when it calls server internal endpoints.
pub struct ControlJwksCache {
    control_url: String,
    http_client: reqwest::Client,
    cache: Cache<String, Arc<ControlJwks>>,
    #[allow(dead_code)] // Used for documentation purposes
    cache_ttl: std::time::Duration,
}

impl ControlJwksCache {
    /// Create a new Control JWKS cache
    ///
    /// # Arguments
    ///
    /// * `control_url` - Base URL of the Control (e.g., "http://localhost:8081")
    /// * `cache_ttl` - How long to cache JWKS before refreshing (recommended: 15 minutes)
    pub fn new(control_url: String, cache_ttl: std::time::Duration) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client for Control JWKS");

        let cache = Cache::builder()
            .time_to_live(cache_ttl)
            .max_capacity(10) // Small cache, only one entry needed
            .build();

        Self { control_url, http_client, cache, cache_ttl }
    }

    /// Fetch JWKS from Control
    async fn fetch_jwks(&self) -> Result<ControlJwks, AuthError> {
        let jwks_url = format!("{}/internal/control-jwks.json", self.control_url);

        tracing::debug!(
            jwks_url = %jwks_url,
            "Fetching Control JWKS"
        );

        let response =
            self.http_client.get(&jwks_url).send().await.map_err(|e| {
                AuthError::JwksError(format!("Failed to fetch Control JWKS: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(AuthError::JwksError(format!(
                "Control JWKS endpoint returned status: {}",
                response.status()
            )));
        }

        let jwks: ControlJwks = response.json().await.map_err(|e| {
            AuthError::JwksError(format!("Failed to parse Control JWKS JSON: {}", e))
        })?;

        tracing::info!(key_count = jwks.keys.len(), "Successfully fetched Control JWKS");

        Ok(jwks)
    }

    /// Get JWKS from cache or fetch if not cached
    async fn get_jwks(&self) -> Result<Arc<ControlJwks>, AuthError> {
        // Use a constant cache key since there's only one Control
        let cache_key = "management_jwks";

        // Try cache first
        if let Some(cached) = self.cache.get(cache_key).await {
            tracing::debug!("Control JWKS cache hit");
            return Ok(cached);
        }

        // Cache miss - fetch fresh
        tracing::debug!("Control JWKS cache miss, fetching fresh");
        let jwks = self.fetch_jwks().await?;
        let jwks = Arc::new(jwks);

        // Store in cache
        self.cache.insert(cache_key.to_string(), Arc::clone(&jwks)).await;

        Ok(jwks)
    }

    /// Get a specific key by key ID
    async fn get_key(&self, kid: &str) -> Result<ControlJwk, AuthError> {
        let jwks = self.get_jwks().await?;

        jwks.keys
            .iter()
            .find(|k| k.kid == kid)
            .cloned()
            .ok_or_else(|| AuthError::JwksError(format!("Control key '{}' not found in JWKS", kid)))
    }

    /// Verify a JWT from the Control
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token from the Control
    ///
    /// # Returns
    ///
    /// Returns the validated JWT claims if verification succeeds
    pub async fn verify_control_jwt(&self, token: &str) -> Result<ControlJwtClaims, AuthError> {
        // Decode header to get key ID
        let header = decode_jwt_header(token)?;

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidTokenFormat("Control JWT missing kid".into()))?;

        // Validate algorithm
        let alg_str = format!("{:?}", header.alg);
        crate::validation::validate_algorithm(&alg_str)?;

        // Get key from JWKS
        let jwk = self.get_key(&kid).await?;
        let decoding_key = jwk.to_decoding_key()?;

        // Verify signature using ControlJwtClaims (not JwtClaims)
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let token_data =
            jsonwebtoken::decode::<ControlJwtClaims>(token, &decoding_key, &validation)
                .map_err(|e| AuthError::InvalidTokenFormat(format!("JWT error: {}", e)))?;

        let mgmt_claims = token_data.claims;

        // Validate claims
        validate_control_claims(&mgmt_claims)?;

        Ok(mgmt_claims)
    }
}

/// Discovery-aware Control JWKS cache
///
/// This cache supports multi-instance Control service deployments by:
/// 1. Discovering all Control service pod IPs (when discovery is enabled)
/// 2. Fetching JWKS from each discovered endpoint in parallel
/// 3. Aggregating all keys by `kid` (key ID)
/// 4. Validating JWTs using any key from any Control instance
///
/// When discovery is disabled, it falls back to single-URL behavior.
pub struct AggregatedControlJwksCache {
    /// Discovery mode
    discovery_mode: DiscoveryMode,
    /// Fallback URL (for development/None mode)
    fallback_url: String,
    /// HTTP client
    http_client: reqwest::Client,
    /// Aggregated keys cache (kid -> key)
    keys_cache: Cache<String, Arc<ControlJwk>>,
    /// Discovered endpoints (cached for refresh)
    endpoints: RwLock<Vec<Endpoint>>,
    /// Cache TTL (used for documentation/configuration purposes)
    #[allow(dead_code)]
    cache_ttl: std::time::Duration,
}

impl AggregatedControlJwksCache {
    /// Create a new discovery-aware Control JWKS cache
    ///
    /// # Arguments
    ///
    /// * `discovery_mode` - The service discovery mode (None, Kubernetes, or Tailscale)
    /// * `fallback_url` - URL to use when discovery is disabled (e.g., "http://localhost:9091")
    /// * `cache_ttl` - How long to cache JWKS before refreshing (recommended: 15 minutes)
    pub fn new(
        discovery_mode: DiscoveryMode,
        fallback_url: String,
        cache_ttl: std::time::Duration,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client for Control JWKS");

        // Max capacity is higher to support multiple keys from multiple instances
        let keys_cache = Cache::builder()
            .time_to_live(cache_ttl)
            .max_capacity(100) // Support up to 100 unique keys
            .build();

        Self {
            discovery_mode,
            fallback_url,
            http_client,
            keys_cache,
            endpoints: RwLock::new(Vec::new()),
            cache_ttl,
        }
    }

    /// Discover Control service endpoints
    async fn discover_endpoints(&self) -> Result<Vec<Endpoint>, AuthError> {
        match &self.discovery_mode {
            DiscoveryMode::None => {
                // No discovery - use fallback URL as single endpoint
                Ok(vec![Endpoint::healthy(self.fallback_url.clone())])
            },
            DiscoveryMode::Kubernetes => {
                // Kubernetes discovery
                let discovery =
                    inferadb_engine_discovery::KubernetesServiceDiscovery::new().await.map_err(
                        |e| AuthError::JwksError(format!("Failed to create K8s discovery: {}", e)),
                    )?;

                let endpoints = discovery.discover(&self.fallback_url).await.map_err(|e| {
                    tracing::warn!(
                        error = %e,
                        fallback_url = %self.fallback_url,
                        "Failed to discover Control endpoints, using fallback"
                    );
                    AuthError::JwksError(format!("Discovery failed: {}", e))
                })?;

                // Filter to only healthy endpoints
                let healthy: Vec<_> =
                    endpoints.into_iter().filter(|e| e.health == EndpointHealth::Healthy).collect();

                if healthy.is_empty() {
                    return Err(AuthError::JwksError("No healthy Control endpoints found".into()));
                }

                tracing::info!(
                    endpoint_count = healthy.len(),
                    "Discovered Control service endpoints"
                );

                Ok(healthy)
            },
        }
    }

    /// Fetch JWKS from a single endpoint
    async fn fetch_jwks_from_endpoint(&self, endpoint_url: &str) -> Result<ControlJwks, String> {
        let jwks_url = format!("{}/internal/control-jwks.json", endpoint_url);

        tracing::debug!(
            jwks_url = %jwks_url,
            "Fetching Control JWKS from endpoint"
        );

        let response = self
            .http_client
            .get(&jwks_url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch JWKS from {}: {}", jwks_url, e))?;

        if !response.status().is_success() {
            return Err(format!(
                "JWKS endpoint {} returned status: {}",
                jwks_url,
                response.status()
            ));
        }

        let jwks: ControlJwks = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse JWKS JSON from {}: {}", jwks_url, e))?;

        tracing::debug!(
            endpoint_url = %endpoint_url,
            key_count = jwks.keys.len(),
            "Fetched JWKS from endpoint"
        );

        Ok(jwks)
    }

    /// Refresh keys from all discovered endpoints
    async fn refresh_keys(&self) -> Result<(), AuthError> {
        // Discover endpoints
        let endpoints = match self.discover_endpoints().await {
            Ok(eps) => eps,
            Err(e) => {
                // On discovery failure, fall back to cached endpoints or fallback URL
                let cached = self.endpoints.read().await;
                if cached.is_empty() {
                    tracing::warn!(
                        error = %e,
                        "Discovery failed and no cached endpoints, using fallback URL"
                    );
                    vec![Endpoint::healthy(self.fallback_url.clone())]
                } else {
                    tracing::warn!(
                        error = %e,
                        cached_count = cached.len(),
                        "Discovery failed, using cached endpoints"
                    );
                    cached.clone()
                }
            },
        };

        // Update cached endpoints
        {
            let mut eps = self.endpoints.write().await;
            *eps = endpoints.clone();
        }

        // Fetch JWKS from all endpoints in parallel
        let fetch_futures: Vec<_> =
            endpoints.iter().map(|ep| self.fetch_jwks_from_endpoint(&ep.url)).collect();

        let results = futures::future::join_all(fetch_futures).await;

        // Aggregate keys from all successful fetches
        let mut aggregated_keys = 0;
        for (endpoint, result) in endpoints.iter().zip(results) {
            match result {
                Ok(jwks) => {
                    for key in jwks.keys {
                        self.keys_cache.insert(key.kid.clone(), Arc::new(key)).await;
                        aggregated_keys += 1;
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        endpoint = %endpoint.url,
                        error = %e,
                        "Failed to fetch JWKS from endpoint"
                    );
                },
            }
        }

        if aggregated_keys == 0 {
            return Err(AuthError::JwksError(
                "Failed to fetch any JWKS from discovered endpoints".into(),
            ));
        }

        tracing::info!(
            aggregated_keys = aggregated_keys,
            endpoint_count = endpoints.len(),
            "Aggregated Control JWKS from discovered endpoints"
        );

        Ok(())
    }

    /// Get a specific key by key ID
    async fn get_key(&self, kid: &str) -> Result<Arc<ControlJwk>, AuthError> {
        // Try cache first
        if let Some(key) = self.keys_cache.get(kid).await {
            tracing::debug!(kid = %kid, "Control key cache hit");
            return Ok(key);
        }

        // Cache miss - refresh keys from all endpoints
        tracing::debug!(kid = %kid, "Control key cache miss, refreshing from endpoints");
        self.refresh_keys().await?;

        // Try cache again after refresh
        self.keys_cache.get(kid).await.ok_or_else(|| {
            AuthError::JwksError(format!("Control key '{}' not found in any discovered JWKS", kid))
        })
    }

    /// Verify a JWT from the Control
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token from the Control
    ///
    /// # Returns
    ///
    /// Returns the validated JWT claims if verification succeeds
    pub async fn verify_control_jwt(&self, token: &str) -> Result<ControlJwtClaims, AuthError> {
        // Decode header to get key ID
        let header = decode_jwt_header(token)?;

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidTokenFormat("Control JWT missing kid".into()))?;

        // Validate algorithm
        let alg_str = format!("{:?}", header.alg);
        crate::validation::validate_algorithm(&alg_str)?;

        // Get key from aggregated JWKS (may trigger discovery + fetch)
        let jwk = self.get_key(&kid).await?;
        let decoding_key = jwk.to_decoding_key()?;

        // Verify signature using ControlJwtClaims (not JwtClaims)
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let token_data =
            jsonwebtoken::decode::<ControlJwtClaims>(token, &decoding_key, &validation)
                .map_err(|e| AuthError::InvalidTokenFormat(format!("JWT error: {}", e)))?;

        let mgmt_claims = token_data.claims;

        // Validate claims
        validate_control_claims(&mgmt_claims)?;

        Ok(mgmt_claims)
    }

    /// Get the number of cached keys (for diagnostics)
    pub fn cached_key_count(&self) -> u64 {
        self.keys_cache.entry_count()
    }
}

/// JWT claims from Control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlJwtClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    jti: Option<String>,
}

/// Validate Control JWT claims
pub fn validate_control_claims(claims: &ControlJwtClaims) -> Result<(), AuthError> {
    let now = chrono::Utc::now().timestamp() as u64;

    // Check expiration
    if claims.exp <= now {
        return Err(AuthError::TokenExpired);
    }

    // Check issued-at is reasonable (not in future, not too old)
    if claims.iat > now {
        return Err(AuthError::InvalidTokenFormat("iat claim is in the future".into()));
    }
    if now - claims.iat > 86400 {
        // 24 hours
        return Err(AuthError::InvalidTokenFormat("iat claim is too old (> 24 hours)".into()));
    }

    // Validate subject format: "control:{control_id}" (from Control identity)
    if !claims.sub.starts_with("control:") {
        return Err(AuthError::InvalidTokenFormat(
            "Control JWT subject must start with 'control:'".into(),
        ));
    }

    Ok(())
}

/// Extract Control ID from JWT claims
fn extract_control_id(claims: &ControlJwtClaims) -> Result<String, AuthError> {
    // Subject format: "control:{control_id}" (from Control identity)
    claims
        .sub
        .strip_prefix("control:")
        .ok_or_else(|| {
            AuthError::InvalidTokenFormat("Control JWT subject must start with 'control:'".into())
        })
        .map(|s| s.to_string())
}

/// Axum middleware for Control JWT authentication
///
/// This middleware:
/// 1. Extracts the bearer token from the Authorization header
/// 2. Verifies the JWT using Control's JWKS
/// 3. Creates a ControlContext from the validated claims
/// 4. Injects the context into request extensions
///
/// # Arguments
///
/// * `jwks_cache` - The Control JWKS cache for verifying signatures
/// * `request` - The incoming HTTP request
/// * `next` - The next layer in the middleware stack
///
/// # Returns
///
/// Returns the response from the next layer, or an error response if authentication fails
///
/// # Security
///
/// This middleware should ONLY be applied to internal endpoints that should be
/// callable by the Control (like cache invalidation callbacks).
pub async fn control_auth_middleware(
    jwks_cache: Arc<ControlJwksCache>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract bearer token
    let token = extract_bearer_token(request.headers()).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Control authentication failed: missing or invalid token"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Control token: {}", e)).into_response()
    })?;

    // Verify JWT
    let claims = jwks_cache.verify_control_jwt(&token).await.map_err(|e| {
        tracing::warn!(
            error = %e,
            "Control JWT verification failed"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Control JWT: {}", e)).into_response()
    })?;

    // Extract Control ID
    let control_id = extract_control_id(&claims).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Failed to extract Control ID from JWT"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Control JWT: {}", e)).into_response()
    })?;

    // Create ControlContext
    let context = ControlContext {
        control_id: control_id.clone(),
        jti: claims.jti,
        issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
            .unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(300)),
    };

    tracing::info!(
        control_id = %control_id,
        event_type = "control.auth_success",
        "Control authenticated successfully"
    );

    // Insert context into request extensions
    request.extensions_mut().insert(Arc::new(context));

    // Continue to next middleware/handler
    Ok(next.run(request).await)
}

/// Axum middleware for Control authentication using aggregated discovery-aware JWKS cache
///
/// This middleware verifies JWTs issued by any discovered Control instance.
/// Use this when service discovery is enabled to validate tokens from multiple
/// Control service instances.
///
/// # Security
///
/// This middleware should ONLY be applied to internal endpoints that should be
/// callable by the Control (like cache invalidation callbacks).
pub async fn aggregated_control_auth_middleware(
    jwks_cache: Arc<AggregatedControlJwksCache>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract bearer token
    let token = extract_bearer_token(request.headers()).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Control authentication failed: missing or invalid token"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Control token: {}", e)).into_response()
    })?;

    // Verify JWT using aggregated cache (may trigger discovery + fetch)
    let claims = jwks_cache.verify_control_jwt(&token).await.map_err(|e| {
        tracing::warn!(
            error = %e,
            "Control JWT verification failed"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Control JWT: {}", e)).into_response()
    })?;

    // Extract Control ID
    let control_id = extract_control_id(&claims).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Failed to extract Control ID from JWT"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Control JWT: {}", e)).into_response()
    })?;

    // Create ControlContext
    let context = ControlContext {
        control_id: control_id.clone(),
        jti: claims.jti,
        issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
            .unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(300)),
    };

    tracing::info!(
        control_id = %control_id,
        event_type = "control.auth_success",
        "Control authenticated successfully (aggregated)"
    );

    // Insert context into request extensions
    request.extensions_mut().insert(Arc::new(context));

    // Continue to next middleware/handler
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_control_claims_valid() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = ControlJwtClaims {
            iss: "inferadb-control:ctrl-test".to_string(),
            sub: "control:ctrl-test".to_string(),
            aud: "inferadb-engine".to_string(),
            exp: now + 300,
            iat: now,
            jti: Some("test-jti".to_string()),
        };

        assert!(validate_control_claims(&claims).is_ok());
    }

    #[test]
    fn test_validate_control_claims_expired() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = ControlJwtClaims {
            iss: "inferadb-control:ctrl-test".to_string(),
            sub: "control:ctrl-test".to_string(),
            aud: "inferadb-engine".to_string(),
            exp: now - 100, // Expired
            iat: now - 400,
            jti: Some("test-jti".to_string()),
        };

        assert!(matches!(validate_control_claims(&claims), Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_validate_control_claims_invalid_subject() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = ControlJwtClaims {
            iss: "inferadb-control:ctrl-test".to_string(),
            sub: "invalid-subject".to_string(), // Should start with "control:"
            aud: "inferadb-engine".to_string(),
            exp: now + 300,
            iat: now,
            jti: Some("test-jti".to_string()),
        };

        assert!(matches!(validate_control_claims(&claims), Err(AuthError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_extract_control_id() {
        let claims = ControlJwtClaims {
            iss: "inferadb-control:ctrl-prod-instance-1".to_string(),
            sub: "control:ctrl-prod-instance-1".to_string(),
            aud: "inferadb-engine".to_string(),
            exp: 0,
            iat: 0,
            jti: None,
        };

        let id = extract_control_id(&claims).unwrap();
        assert_eq!(id, "ctrl-prod-instance-1");
    }

    #[test]
    fn test_extract_control_id_invalid() {
        let claims = ControlJwtClaims {
            iss: "inferadb-control:ctrl-test".to_string(),
            sub: "invalid:format".to_string(),
            aud: "inferadb-engine".to_string(),
            exp: 0,
            iat: 0,
            jti: None,
        };

        assert!(extract_control_id(&claims).is_err());
    }
}
