//! Management API JWT authentication middleware
//!
//! This module provides authentication for requests FROM the Management API TO the server.
//! This is the reverse of the normal flow where the server validates client JWTs issued by
//! Management.
//!
//! The Management API uses this to authenticate when calling server internal endpoints
//! (like cache invalidation callbacks).

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use moka::future::Cache;
use serde::{Deserialize, Serialize};

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
struct ManagementJwks {
    keys: Vec<ManagementJwk>,
}

/// JWK from Management API JWKS endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagementJwk {
    kty: String,
    alg: String,
    kid: String,
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
