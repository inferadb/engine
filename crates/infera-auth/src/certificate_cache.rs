//! Certificate caching for JWT validation using JWKS
//!
//! This module provides certificate caching for Ed25519 public keys fetched from
//! the Management API's JWKS endpoint. It parses JWT `kid` headers in the format
//! `"org-{org_id}-client-{client_id}-cert-{cert_id}"` and fetches the corresponding
//! key from the organization's JWKS.

use std::{sync::Arc, time::Duration};

use base64::Engine;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use reqwest::Client as HttpClient;

use crate::metrics::AuthMetrics;

/// Parsed key ID from JWT header
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParsedKeyId {
    /// Organization ID (Snowflake ID)
    pub org_id: i64,
    /// Client ID (Snowflake ID)
    pub client_id: i64,
    /// Certificate ID (Snowflake ID)
    pub cert_id: i64,
}

impl ParsedKeyId {
    /// Parse kid in format "org-{org_id}-client-{client_id}-cert-{cert_id}"
    pub fn parse(kid: &str) -> Result<Self, KeyIdParseError> {
        let parts: Vec<&str> = kid.split('-').collect();

        // Format: org-{snowflake_id}-client-{snowflake_id}-cert-{snowflake_id}
        if parts.len() != 6 {
            return Err(KeyIdParseError::InvalidFormat);
        }

        if parts[0] != "org" || parts[2] != "client" || parts[4] != "cert" {
            return Err(KeyIdParseError::InvalidFormat);
        }

        let org_id = parts[1].parse::<i64>()
            .map_err(|_| KeyIdParseError::InvalidSnowflakeId("org_id"))?;
        let client_id = parts[3].parse::<i64>()
            .map_err(|_| KeyIdParseError::InvalidSnowflakeId("client_id"))?;
        let cert_id = parts[5].parse::<i64>()
            .map_err(|_| KeyIdParseError::InvalidSnowflakeId("cert_id"))?;

        Ok(Self { org_id, client_id, cert_id })
    }

    /// Convert back to kid string format
    pub fn to_kid(&self) -> String {
        format!("org-{}-client-{}-cert-{}", self.org_id, self.client_id, self.cert_id)
    }
}

/// JWKS response from Management API
#[derive(Debug, serde::Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// JSON Web Key from JWKS
#[derive(Debug, serde::Deserialize)]
struct Jwk {
    /// Key ID
    kid: String,
    /// Key type (should be "OKP" for Ed25519)
    kty: String,
    /// Curve (should be "Ed25519")
    #[serde(default)]
    crv: Option<String>,
    /// Base64url-encoded public key
    #[serde(default)]
    x: Option<String>,
    /// Algorithm
    #[serde(default)]
    alg: Option<String>,
}

/// Certificate cache that fetches keys from JWKS
pub struct CertificateCache {
    http_client: HttpClient,
    management_api_url: String,
    cache: Cache<ParsedKeyId, Arc<DecodingKey>>,
    metrics: Option<Arc<AuthMetrics>>,
}

impl CertificateCache {
    /// Create a new certificate cache
    ///
    /// # Arguments
    ///
    /// * `management_api_url` - Base URL of the Management API (e.g., "http://management-api:8081")
    /// * `ttl` - Time-to-live for cached certificates
    /// * `max_capacity` - Maximum number of certificates to cache
    pub fn new(management_api_url: String, ttl: Duration, max_capacity: u64) -> Result<Self, CertificateCacheError> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| CertificateCacheError::HttpClientError(e.to_string()))?;

        Ok(Self {
            http_client,
            management_api_url,
            cache: Cache::builder().time_to_live(ttl).max_capacity(max_capacity).build(),
            metrics: None,
        })
    }

    /// Create a new certificate cache with metrics
    pub fn new_with_metrics(
        management_api_url: String,
        ttl: Duration,
        max_capacity: u64,
        metrics: Arc<AuthMetrics>,
    ) -> Result<Self, CertificateCacheError> {
        let mut cache = Self::new(management_api_url, ttl, max_capacity)?;
        cache.metrics = Some(metrics);
        Ok(cache)
    }

    /// Get decoding key for the given kid, fetching from JWKS if not cached
    pub async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> Result<Arc<DecodingKey>, CertificateCacheError> {
        let parsed_kid = ParsedKeyId::parse(kid)?;

        // Check cache first
        if let Some(key) = self.cache.get(&parsed_kid).await {
            if let Some(ref metrics) = self.metrics {
                metrics.record_cache_hit("certificate");
            }
            return Ok(key);
        }

        // Record cache miss
        if let Some(ref metrics) = self.metrics {
            metrics.record_cache_miss("certificate");
        }

        // Fetch from JWKS endpoint
        let jwks_url = format!("{}/v1/organizations/{}/jwks.json", self.management_api_url, parsed_kid.org_id);

        tracing::debug!(
            jwks_url = %jwks_url,
            kid = %kid,
            "Fetching JWKS from Management API"
        );

        let response = self.http_client
            .get(&jwks_url)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(
                    jwks_url = %jwks_url,
                    error = %e,
                    "Failed to fetch JWKS"
                );
                if let Some(ref metrics) = self.metrics {
                    metrics.record_management_api_call("get_jwks", 0);
                }
                CertificateCacheError::JwksFetchError(e.to_string())
            })?;

        let status = response.status();
        if let Some(ref metrics) = self.metrics {
            metrics.record_management_api_call("get_jwks", status.as_u16());
        }

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CertificateCacheError::CertificateNotFound);
        }

        if !status.is_success() {
            return Err(CertificateCacheError::JwksFetchError(format!("HTTP {}", status)));
        }

        let jwks: JwksResponse = response.json().await
            .map_err(|e| CertificateCacheError::JwksFetchError(e.to_string()))?;

        tracing::debug!(
            keys_count = jwks.keys.len(),
            keys = ?jwks.keys.iter().map(|k| &k.kid).collect::<Vec<_>>(),
            "JWKS response received"
        );

        // Find the key matching our kid
        let target_kid = parsed_kid.to_kid();
        let jwk = jwks.keys.into_iter()
            .find(|k| k.kid == target_kid)
            .ok_or_else(|| {
                tracing::warn!(
                    target_kid = %target_kid,
                    "Certificate not found in JWKS"
                );
                CertificateCacheError::CertificateNotFound
            })?;

        // Validate key type
        if jwk.kty != "OKP" {
            return Err(CertificateCacheError::UnsupportedAlgorithm(format!("key type: {}", jwk.kty)));
        }

        if jwk.crv.as_deref() != Some("Ed25519") {
            return Err(CertificateCacheError::UnsupportedAlgorithm(
                format!("curve: {:?}", jwk.crv)
            ));
        }

        let x = jwk.x.ok_or_else(|| {
            CertificateCacheError::InvalidPublicKey("missing 'x' parameter".to_string())
        })?;

        // Decode base64url public key
        let public_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&x)
            .map_err(|e| CertificateCacheError::InvalidPublicKey(e.to_string()))?;

        // Verify key length (Ed25519 public keys are 32 bytes)
        if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(CertificateCacheError::InvalidPublicKey(format!(
                "Expected {} bytes, got {}",
                PUBLIC_KEY_LENGTH,
                public_key_bytes.len()
            )));
        }

        // Validate it's a valid Ed25519 key
        let _verifying_key = VerifyingKey::from_bytes(
            public_key_bytes.as_slice().try_into().map_err(|_| {
                CertificateCacheError::InvalidPublicKey("Failed to convert bytes".to_string())
            })?
        ).map_err(|e| CertificateCacheError::InvalidPublicKey(e.to_string()))?;

        // Convert to jsonwebtoken DecodingKey
        let decoding_key = DecodingKey::from_ed_components(&x)
            .map_err(|e| CertificateCacheError::InvalidPublicKey(e.to_string()))?;
        let decoding_key = Arc::new(decoding_key);

        // Cache it
        self.cache.insert(parsed_kid, decoding_key.clone()).await;

        Ok(decoding_key)
    }
}

/// Error parsing key ID from JWT header
#[derive(Debug, thiserror::Error)]
pub enum KeyIdParseError {
    /// Invalid kid format
    #[error("Invalid kid format (expected: org-{{org_id}}-client-{{client_id}}-cert-{{cert_id}})")]
    InvalidFormat,

    /// Invalid Snowflake ID
    #[error("Invalid Snowflake ID in {0}")]
    InvalidSnowflakeId(&'static str),
}

/// Error fetching or decoding certificate
#[derive(Debug, thiserror::Error)]
pub enum CertificateCacheError {
    /// Invalid kid format
    #[error("Invalid kid: {0}")]
    InvalidKeyId(#[from] KeyIdParseError),

    /// Certificate not found in JWKS
    #[error("Certificate not found")]
    CertificateNotFound,

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// JWKS fetch failed
    #[error("JWKS fetch error: {0}")]
    JwksFetchError(String),

    /// HTTP client creation failed
    #[error("HTTP client error: {0}")]
    HttpClientError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_kid() {
        let kid = "org-11897886526013449-client-11897886528110597-cert-11897886528176133";
        let parsed = ParsedKeyId::parse(kid).unwrap();

        assert_eq!(parsed.org_id, 11897886526013449i64);
        assert_eq!(parsed.client_id, 11897886528110597i64);
        assert_eq!(parsed.cert_id, 11897886528176133i64);
    }

    #[test]
    fn test_parse_invalid_format_wrong_prefix() {
        let kid = "organization-11897886526013449-client-11897886528110597-cert-11897886528176133";
        assert!(matches!(ParsedKeyId::parse(kid), Err(KeyIdParseError::InvalidFormat)));
    }

    #[test]
    fn test_parse_invalid_snowflake_id() {
        let kid = "org-not_a_number-client-11897886528110597-cert-11897886528176133";
        assert!(matches!(ParsedKeyId::parse(kid), Err(KeyIdParseError::InvalidSnowflakeId(_))));
    }

    #[test]
    fn test_parsed_key_id_to_kid() {
        let parsed = ParsedKeyId {
            org_id: 123,
            client_id: 456,
            cert_id: 789,
        };
        assert_eq!(parsed.to_kid(), "org-123-client-456-cert-789");
    }
}
