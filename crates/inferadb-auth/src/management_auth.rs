//! Management API JWT authentication middleware
//!
//! This module provides authentication for requests FROM the Management API TO the server.
//! This is the reverse of the normal flow where the server validates client JWTs issued by
//! Management.
//!
//! The Management API uses this to authenticate when calling server internal endpoints
//! (like cache invalidation callbacks).
//!
//! ## Discovery Support
//!
//! When service discovery is enabled (Kubernetes or Tailscale), the cache will:
//! 1. Discover all management service pod IPs
//! 2. Fetch JWKS from each discovered endpoint
//! 3. Aggregate all keys by `kid` (key ID)
//! 4. Validate JWTs using any key from any management instance
//!
//! This allows the server to validate JWTs signed by any management service instance
//! in a distributed deployment.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_config::DiscoveryMode;
use inferadb_discovery::{Endpoint, EndpointDiscovery, EndpointHealth};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{error::AuthError, jwt::decode_jwt_header, middleware::extract_bearer_token};

/// Management context attached to requests authenticated by Management API
#[derive(Clone, Debug)]
pub struct ManagementContext {
    /// Management API instance ID (from JWT subject: "management:{management_id}")
    pub management_id: String,
    /// JWT ID for replay protection
    pub jti: Option<String>,
    /// When the token was issued
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// When the token expires
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// JWKS response from Management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementJwks {
    /// List of JWKs
    pub keys: Vec<ManagementJwk>,
}

/// JWK from Management API JWKS endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementJwk {
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

impl ManagementJwk {
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

/// Management API JWKS cache
///
/// This cache fetches and caches the Management API's public keys from its
/// /.well-known/jwks.json endpoint. These keys are used to verify JWTs signed
/// by the Management API when it calls server internal endpoints.
pub struct ManagementJwksCache {
    management_api_url: String,
    http_client: reqwest::Client,
    cache: Cache<String, Arc<ManagementJwks>>,
    #[allow(dead_code)] // Used for documentation purposes
    cache_ttl: std::time::Duration,
}

impl ManagementJwksCache {
    /// Create a new Management JWKS cache
    ///
    /// # Arguments
    ///
    /// * `management_api_url` - Base URL of the Management API (e.g., "http://localhost:8081")
    /// * `cache_ttl` - How long to cache JWKS before refreshing (recommended: 15 minutes)
    pub fn new(management_api_url: String, cache_ttl: std::time::Duration) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client for Management JWKS");

        let cache = Cache::builder()
            .time_to_live(cache_ttl)
            .max_capacity(10) // Small cache, only one entry needed
            .build();

        Self { management_api_url, http_client, cache, cache_ttl }
    }

    /// Fetch JWKS from Management API
    async fn fetch_jwks(&self) -> Result<ManagementJwks, AuthError> {
        let jwks_url = format!("{}/internal/management-jwks.json", self.management_api_url);

        tracing::debug!(
            jwks_url = %jwks_url,
            "Fetching Management API JWKS"
        );

        let response =
            self.http_client.get(&jwks_url).send().await.map_err(|e| {
                AuthError::JwksError(format!("Failed to fetch Management JWKS: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(AuthError::JwksError(format!(
                "Management JWKS endpoint returned status: {}",
                response.status()
            )));
        }

        let jwks: ManagementJwks = response.json().await.map_err(|e| {
            AuthError::JwksError(format!("Failed to parse Management JWKS JSON: {}", e))
        })?;

        tracing::info!(key_count = jwks.keys.len(), "Successfully fetched Management API JWKS");

        Ok(jwks)
    }

    /// Get JWKS from cache or fetch if not cached
    async fn get_jwks(&self) -> Result<Arc<ManagementJwks>, AuthError> {
        // Use a constant cache key since there's only one Management API
        let cache_key = "management_jwks";

        // Try cache first
        if let Some(cached) = self.cache.get(cache_key).await {
            tracing::debug!("Management JWKS cache hit");
            return Ok(cached);
        }

        // Cache miss - fetch fresh
        tracing::debug!("Management JWKS cache miss, fetching fresh");
        let jwks = self.fetch_jwks().await?;
        let jwks = Arc::new(jwks);

        // Store in cache
        self.cache.insert(cache_key.to_string(), Arc::clone(&jwks)).await;

        Ok(jwks)
    }

    /// Get a specific key by key ID
    async fn get_key(&self, kid: &str) -> Result<ManagementJwk, AuthError> {
        let jwks = self.get_jwks().await?;

        jwks.keys.iter().find(|k| k.kid == kid).cloned().ok_or_else(|| {
            AuthError::JwksError(format!("Management key '{}' not found in JWKS", kid))
        })
    }

    /// Verify a JWT from the Management API
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token from the Management API
    ///
    /// # Returns
    ///
    /// Returns the validated JWT claims if verification succeeds
    pub async fn verify_management_jwt(
        &self,
        token: &str,
    ) -> Result<ManagementJwtClaims, AuthError> {
        // Decode header to get key ID
        let header = decode_jwt_header(token)?;

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidTokenFormat("Management JWT missing kid".into()))?;

        // Validate algorithm
        let alg_str = format!("{:?}", header.alg);
        crate::validation::validate_algorithm(
            &alg_str,
            &["EdDSA".to_string(), "RS256".to_string()],
        )?;

        // Get key from JWKS
        let jwk = self.get_key(&kid).await?;
        let decoding_key = jwk.to_decoding_key()?;

        // Verify signature using ManagementJwtClaims (not JwtClaims)
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let token_data =
            jsonwebtoken::decode::<ManagementJwtClaims>(token, &decoding_key, &validation)
                .map_err(|e| AuthError::InvalidTokenFormat(format!("JWT error: {}", e)))?;

        let mgmt_claims = token_data.claims;

        // Validate claims
        validate_management_claims(&mgmt_claims)?;

        Ok(mgmt_claims)
    }
}

/// Discovery-aware Management API JWKS cache
///
/// This cache supports multi-instance management service deployments by:
/// 1. Discovering all management service pod IPs (when discovery is enabled)
/// 2. Fetching JWKS from each discovered endpoint in parallel
/// 3. Aggregating all keys by `kid` (key ID)
/// 4. Validating JWTs using any key from any management instance
///
/// When discovery is disabled, it falls back to single-URL behavior.
pub struct AggregatedManagementJwksCache {
    /// Discovery mode
    discovery_mode: DiscoveryMode,
    /// Fallback URL (for development/None mode)
    fallback_url: String,
    /// HTTP client
    http_client: reqwest::Client,
    /// Aggregated keys cache (kid -> key)
    keys_cache: Cache<String, Arc<ManagementJwk>>,
    /// Discovered endpoints (cached for refresh)
    endpoints: RwLock<Vec<Endpoint>>,
    /// Cache TTL (used for documentation/configuration purposes)
    #[allow(dead_code)]
    cache_ttl: std::time::Duration,
}

impl AggregatedManagementJwksCache {
    /// Create a new discovery-aware Management JWKS cache
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
            .expect("Failed to create HTTP client for Management JWKS");

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

    /// Discover management service endpoints
    async fn discover_endpoints(&self) -> Result<Vec<Endpoint>, AuthError> {
        match &self.discovery_mode {
            DiscoveryMode::None => {
                // No discovery - use fallback URL as single endpoint
                Ok(vec![Endpoint::healthy(self.fallback_url.clone())])
            },
            DiscoveryMode::Kubernetes => {
                // Kubernetes discovery
                let discovery =
                    inferadb_discovery::KubernetesServiceDiscovery::new().await.map_err(|e| {
                        AuthError::JwksError(format!("Failed to create K8s discovery: {}", e))
                    })?;

                let endpoints = discovery.discover(&self.fallback_url).await.map_err(|e| {
                    tracing::warn!(
                        error = %e,
                        fallback_url = %self.fallback_url,
                        "Failed to discover management endpoints, using fallback"
                    );
                    AuthError::JwksError(format!("Discovery failed: {}", e))
                })?;

                // Filter to only healthy endpoints
                let healthy: Vec<_> =
                    endpoints.into_iter().filter(|e| e.health == EndpointHealth::Healthy).collect();

                if healthy.is_empty() {
                    return Err(AuthError::JwksError(
                        "No healthy management endpoints found".into(),
                    ));
                }

                tracing::info!(
                    endpoint_count = healthy.len(),
                    "Discovered management service endpoints"
                );

                Ok(healthy)
            },
            DiscoveryMode::Tailscale { local_cluster, remote_clusters } => {
                // Tailscale discovery
                let remote_configs: Vec<_> = remote_clusters
                    .iter()
                    .map(|rc| inferadb_discovery::RemoteClusterConfig {
                        name: rc.name.clone(),
                        tailscale_domain: rc.tailscale_domain.clone(),
                        service_name: rc.service_name.clone(),
                        port: rc.port,
                    })
                    .collect();

                let discovery = inferadb_discovery::TailscaleServiceDiscovery::new(
                    local_cluster.clone(),
                    remote_configs,
                );

                let endpoints = discovery.discover(&self.fallback_url).await.map_err(|e| {
                    tracing::warn!(
                        error = %e,
                        fallback_url = %self.fallback_url,
                        "Failed to discover management endpoints via Tailscale, using fallback"
                    );
                    AuthError::JwksError(format!("Tailscale discovery failed: {}", e))
                })?;

                let healthy: Vec<_> =
                    endpoints.into_iter().filter(|e| e.health == EndpointHealth::Healthy).collect();

                if healthy.is_empty() {
                    return Err(AuthError::JwksError(
                        "No healthy management endpoints found via Tailscale".into(),
                    ));
                }

                tracing::info!(
                    endpoint_count = healthy.len(),
                    local_cluster = %local_cluster,
                    "Discovered management service endpoints via Tailscale"
                );

                Ok(healthy)
            },
        }
    }

    /// Fetch JWKS from a single endpoint
    async fn fetch_jwks_from_endpoint(&self, endpoint_url: &str) -> Result<ManagementJwks, String> {
        let jwks_url = format!("{}/internal/management-jwks.json", endpoint_url);

        tracing::debug!(
            jwks_url = %jwks_url,
            "Fetching Management API JWKS from endpoint"
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

        let jwks: ManagementJwks = response
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
            "Aggregated management JWKS from discovered endpoints"
        );

        Ok(())
    }

    /// Get a specific key by key ID
    async fn get_key(&self, kid: &str) -> Result<Arc<ManagementJwk>, AuthError> {
        // Try cache first
        if let Some(key) = self.keys_cache.get(kid).await {
            tracing::debug!(kid = %kid, "Management key cache hit");
            return Ok(key);
        }

        // Cache miss - refresh keys from all endpoints
        tracing::debug!(kid = %kid, "Management key cache miss, refreshing from endpoints");
        self.refresh_keys().await?;

        // Try cache again after refresh
        self.keys_cache.get(kid).await.ok_or_else(|| {
            AuthError::JwksError(format!(
                "Management key '{}' not found in any discovered JWKS",
                kid
            ))
        })
    }

    /// Verify a JWT from the Management API
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token from the Management API
    ///
    /// # Returns
    ///
    /// Returns the validated JWT claims if verification succeeds
    pub async fn verify_management_jwt(
        &self,
        token: &str,
    ) -> Result<ManagementJwtClaims, AuthError> {
        // Decode header to get key ID
        let header = decode_jwt_header(token)?;

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidTokenFormat("Management JWT missing kid".into()))?;

        // Validate algorithm
        let alg_str = format!("{:?}", header.alg);
        crate::validation::validate_algorithm(
            &alg_str,
            &["EdDSA".to_string(), "RS256".to_string()],
        )?;

        // Get key from aggregated JWKS (may trigger discovery + fetch)
        let jwk = self.get_key(&kid).await?;
        let decoding_key = jwk.to_decoding_key()?;

        // Verify signature using ManagementJwtClaims (not JwtClaims)
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let token_data =
            jsonwebtoken::decode::<ManagementJwtClaims>(token, &decoding_key, &validation)
                .map_err(|e| AuthError::InvalidTokenFormat(format!("JWT error: {}", e)))?;

        let mgmt_claims = token_data.claims;

        // Validate claims
        validate_management_claims(&mgmt_claims)?;

        Ok(mgmt_claims)
    }

    /// Get the number of cached keys (for diagnostics)
    pub fn cached_key_count(&self) -> u64 {
        self.keys_cache.entry_count()
    }
}

/// JWT claims from Management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementJwtClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    jti: Option<String>,
}

/// Validate Management API JWT claims
fn validate_management_claims(claims: &ManagementJwtClaims) -> Result<(), AuthError> {
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

    // Validate subject format: "management:{management_id}"
    if !claims.sub.starts_with("management:") {
        return Err(AuthError::InvalidTokenFormat(
            "Management JWT subject must start with 'management:'".into(),
        ));
    }

    Ok(())
}

/// Extract management ID from JWT claims
fn extract_management_id(claims: &ManagementJwtClaims) -> Result<String, AuthError> {
    // Subject format: "management:{management_id}"
    claims
        .sub
        .strip_prefix("management:")
        .ok_or_else(|| {
            AuthError::InvalidTokenFormat(
                "Management JWT subject must start with 'management:'".into(),
            )
        })
        .map(|s| s.to_string())
}

/// Axum middleware for Management API JWT authentication
///
/// This middleware:
/// 1. Extracts the bearer token from the Authorization header
/// 2. Verifies the JWT using Management API's JWKS
/// 3. Creates a ManagementContext from the validated claims
/// 4. Injects the context into request extensions
///
/// # Arguments
///
/// * `jwks_cache` - The Management JWKS cache for verifying signatures
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
/// callable by the Management API (like cache invalidation callbacks).
pub async fn management_auth_middleware(
    jwks_cache: Arc<ManagementJwksCache>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract bearer token
    let token = extract_bearer_token(request.headers()).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Management authentication failed: missing or invalid token"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Management API token: {}", e)).into_response()
    })?;

    // Verify JWT
    let claims = jwks_cache.verify_management_jwt(&token).await.map_err(|e| {
        tracing::warn!(
            error = %e,
            "Management JWT verification failed"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Management API JWT: {}", e)).into_response()
    })?;

    // Extract management ID
    let management_id = extract_management_id(&claims).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Failed to extract management ID from JWT"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Management API JWT: {}", e)).into_response()
    })?;

    // Create ManagementContext
    let context = ManagementContext {
        management_id: management_id.clone(),
        jti: claims.jti,
        issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
            .unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(300)),
    };

    tracing::info!(
        management_id = %management_id,
        event_type = "management.auth_success",
        "Management API authenticated successfully"
    );

    // Insert context into request extensions
    request.extensions_mut().insert(Arc::new(context));

    // Continue to next middleware/handler
    Ok(next.run(request).await)
}

/// Axum middleware for Management API authentication using aggregated discovery-aware JWKS cache
///
/// This middleware verifies JWTs issued by any discovered Management API instance.
/// Use this when service discovery is enabled to validate tokens from multiple
/// management service instances.
///
/// # Security
///
/// This middleware should ONLY be applied to internal endpoints that should be
/// callable by the Management API (like cache invalidation callbacks).
pub async fn aggregated_management_auth_middleware(
    jwks_cache: Arc<AggregatedManagementJwksCache>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract bearer token
    let token = extract_bearer_token(request.headers()).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Management authentication failed: missing or invalid token"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Management API token: {}", e)).into_response()
    })?;

    // Verify JWT using aggregated cache (may trigger discovery + fetch)
    let claims = jwks_cache.verify_management_jwt(&token).await.map_err(|e| {
        tracing::warn!(
            error = %e,
            "Management JWT verification failed"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Management API JWT: {}", e)).into_response()
    })?;

    // Extract management ID
    let management_id = extract_management_id(&claims).map_err(|e| {
        tracing::warn!(
            error = %e,
            "Failed to extract management ID from JWT"
        );
        (StatusCode::UNAUTHORIZED, format!("Invalid Management API JWT: {}", e)).into_response()
    })?;

    // Create ManagementContext
    let context = ManagementContext {
        management_id: management_id.clone(),
        jti: claims.jti,
        issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
            .unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(300)),
    };

    tracing::info!(
        management_id = %management_id,
        event_type = "management.auth_success",
        "Management API authenticated successfully (aggregated)"
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
    fn test_validate_management_claims_valid() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = ManagementJwtClaims {
            iss: "inferadb-management".to_string(),
            sub: "management:prod-instance-1".to_string(),
            aud: "inferadb-server".to_string(),
            exp: now + 300,
            iat: now,
            jti: Some("test-jti".to_string()),
        };

        assert!(validate_management_claims(&claims).is_ok());
    }

    #[test]
    fn test_validate_management_claims_expired() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = ManagementJwtClaims {
            iss: "inferadb-management".to_string(),
            sub: "management:prod-instance-1".to_string(),
            aud: "inferadb-server".to_string(),
            exp: now - 100, // Expired
            iat: now - 400,
            jti: Some("test-jti".to_string()),
        };

        assert!(matches!(validate_management_claims(&claims), Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_validate_management_claims_invalid_subject() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = ManagementJwtClaims {
            iss: "inferadb-management".to_string(),
            sub: "invalid-subject".to_string(), // Should start with "management:"
            aud: "inferadb-server".to_string(),
            exp: now + 300,
            iat: now,
            jti: Some("test-jti".to_string()),
        };

        assert!(matches!(
            validate_management_claims(&claims),
            Err(AuthError::InvalidTokenFormat(_))
        ));
    }

    #[test]
    fn test_extract_management_id() {
        let claims = ManagementJwtClaims {
            iss: "inferadb-management".to_string(),
            sub: "management:prod-instance-1".to_string(),
            aud: "inferadb-server".to_string(),
            exp: 0,
            iat: 0,
            jti: None,
        };

        let id = extract_management_id(&claims).unwrap();
        assert_eq!(id, "prod-instance-1");
    }

    #[test]
    fn test_extract_management_id_invalid() {
        let claims = ManagementJwtClaims {
            iss: "inferadb-management".to_string(),
            sub: "invalid:format".to_string(),
            aud: "inferadb-server".to_string(),
            exp: 0,
            iat: 0,
            jti: None,
        };

        assert!(extract_management_id(&claims).is_err());
    }
}
