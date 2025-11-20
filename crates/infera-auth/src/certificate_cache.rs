//! Certificate caching for JWT validation with Management API
//!
//! This module provides certificate caching for Ed25519 public keys fetched from
//! the Management API. It parses JWT `kid` headers in the format
//! `"org-{org_id}-client-{client_id}-cert-{cert_id}"` and fetches the corresponding
//! certificate from the Management API.

use std::{sync::Arc, time::Duration};

use base64::Engine;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use uuid::Uuid;

use crate::{
    management_client::{ManagementApiError, ManagementClient},
    metrics::AuthMetrics,
};

/// Parsed key ID from JWT header
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParsedKeyId {
    /// Organization UUID
    pub org_id: Uuid,
    /// Client UUID
    pub client_id: Uuid,
    /// Certificate UUID
    pub cert_id: Uuid,
}

impl ParsedKeyId {
    /// Parse kid in format "org-{org_id}-client-{client_id}-cert-{cert_id}"
    ///
    /// # Arguments
    ///
    /// * `kid` - Key ID from JWT header
    ///
    /// # Returns
    ///
    /// Returns the parsed key ID components if the format is valid
    ///
    /// # Errors
    ///
    /// Returns `KeyIdParseError` if:
    /// - The format is invalid (wrong number of parts or wrong prefixes)
    /// - Any UUID component cannot be parsed
    ///
    /// # Example
    ///
    /// ```
    /// # use infera_auth::certificate_cache::ParsedKeyId;
    /// # use uuid::Uuid;
    /// let kid = "org-00000000-0000-0000-0000-000000000001-client-00000000-0000-0000-0000-000000000002-cert-00000000-0000-0000-0000-000000000003";
    /// let parsed = ParsedKeyId::parse(kid).unwrap();
    /// assert_eq!(parsed.org_id, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
    /// ```
    pub fn parse(kid: &str) -> Result<Self, KeyIdParseError> {
        let parts: Vec<&str> = kid.split('-').collect();

        // Format: org-{UUID}-client-{UUID}-cert-{UUID}
        // UUID is 5 parts (8-4-4-4-12 hex digits separated by -)
        // So total: 1 + 5 + 1 + 5 + 1 + 5 = 18 parts
        if parts.len() != 18 {
            return Err(KeyIdParseError::InvalidFormat);
        }

        if parts[0] != "org" || parts[6] != "client" || parts[12] != "cert" {
            return Err(KeyIdParseError::InvalidFormat);
        }

        // Reconstruct UUIDs from their parts (each UUID is 5 dash-separated parts)
        let org_id = Uuid::parse_str(&parts[1..6].join("-"))
            .map_err(|_| KeyIdParseError::InvalidUuid("org_id"))?;
        let client_id = Uuid::parse_str(&parts[7..12].join("-"))
            .map_err(|_| KeyIdParseError::InvalidUuid("client_id"))?;
        let cert_id = Uuid::parse_str(&parts[13..18].join("-"))
            .map_err(|_| KeyIdParseError::InvalidUuid("cert_id"))?;

        Ok(Self { org_id, client_id, cert_id })
    }
}

/// Certificate cache with automatic fetching from management API
///
/// This cache stores Ed25519 public keys (as `DecodingKey` instances) fetched from
/// the Management API. Keys are cached with a configurable TTL and maximum capacity.
pub struct CertificateCache {
    management_client: Arc<ManagementClient>,
    cache: Cache<ParsedKeyId, Arc<DecodingKey>>,
    metrics: Option<Arc<AuthMetrics>>,
}

impl CertificateCache {
    /// Create a new certificate cache
    ///
    /// # Arguments
    ///
    /// * `management_client` - Management API client for fetching certificates
    /// * `ttl` - Time-to-live for cached certificates
    /// * `max_capacity` - Maximum number of certificates to cache
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use infera_auth::certificate_cache::CertificateCache;
    /// # use infera_auth::management_client::ManagementClient;
    /// # use std::sync::Arc;
    /// # use std::time::Duration;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let management_client = Arc::new(ManagementClient::new(
    ///     "https://api.inferadb.com".to_string(),
    ///     5000,
    /// )?);
    ///
    /// let cache = CertificateCache::new(
    ///     management_client,
    ///     Duration::from_secs(300),  // 5 minute TTL
    ///     100,                        // Cache up to 100 certificates
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(management_client: Arc<ManagementClient>, ttl: Duration, max_capacity: u64) -> Self {
        Self {
            management_client,
            cache: Cache::builder().time_to_live(ttl).max_capacity(max_capacity).build(),
            metrics: None,
        }
    }

    /// Create a new certificate cache with metrics
    ///
    /// # Arguments
    ///
    /// * `management_client` - Management API client for fetching certificates
    /// * `ttl` - Time-to-live for cached certificates
    /// * `max_capacity` - Maximum number of certificates to cache
    /// * `metrics` - Optional Prometheus metrics collector
    pub fn new_with_metrics(
        management_client: Arc<ManagementClient>,
        ttl: Duration,
        max_capacity: u64,
        metrics: Arc<AuthMetrics>,
    ) -> Self {
        Self {
            management_client,
            cache: Cache::builder().time_to_live(ttl).max_capacity(max_capacity).build(),
            metrics: Some(metrics),
        }
    }

    /// Get decoding key for the given kid, fetching from management API if not cached
    ///
    /// This method:
    /// 1. Parses the `kid` to extract org/client/cert IDs
    /// 2. Checks the cache for an existing key
    /// 3. If not cached, fetches the certificate from the Management API
    /// 4. Validates the certificate (algorithm, key length)
    /// 5. Converts the Ed25519 public key to a `DecodingKey`
    /// 6. Caches the key for future use
    ///
    /// # Arguments
    ///
    /// * `kid` - Key ID from JWT header (format: "org-{org_id}-client-{client_id}-cert-{cert_id}")
    ///
    /// # Returns
    ///
    /// Returns an `Arc<DecodingKey>` that can be used to verify JWT signatures
    ///
    /// # Errors
    ///
    /// Returns `CertificateCacheError` if:
    /// - The `kid` format is invalid
    /// - The certificate is not found in the Management API
    /// - The algorithm is not EdDSA
    /// - The public key is invalid or has wrong length
    /// - The Management API request fails
    pub async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> Result<Arc<DecodingKey>, CertificateCacheError> {
        let parsed_kid = ParsedKeyId::parse(kid)?;

        // Check cache first
        if let Some(key) = self.cache.get(&parsed_kid).await {
            // Record cache hit
            if let Some(ref metrics) = self.metrics {
                metrics.record_cache_hit("certificate");
            }
            return Ok(key);
        }

        // Record cache miss
        if let Some(ref metrics) = self.metrics {
            metrics.record_cache_miss("certificate");
        }

        // Fetch from management API
        let cert = self
            .management_client
            .get_client_certificate(parsed_kid.org_id, parsed_kid.client_id, parsed_kid.cert_id)
            .await
            .map_err(|e| {
                // Record API call status
                if let Some(ref metrics) = self.metrics {
                    let status = match &e {
                        ManagementApiError::NotFound(_) => 404,
                        ManagementApiError::UnexpectedStatus(code) => *code,
                        _ => 500,
                    };
                    metrics.record_management_api_call("get_client_certificate", status);
                }

                match e {
                    ManagementApiError::NotFound(_) => CertificateCacheError::CertificateNotFound,
                    e => CertificateCacheError::ManagementApiError(e.to_string()),
                }
            })?;

        // Record successful API call
        if let Some(ref metrics) = self.metrics {
            metrics.record_management_api_call("get_client_certificate", 200);
        }

        // Verify algorithm
        if cert.algorithm != "EdDSA" {
            return Err(CertificateCacheError::UnsupportedAlgorithm(cert.algorithm));
        }

        // Decode base64 public key
        let public_key_bytes =
            base64::engine::general_purpose::STANDARD
                .decode(&cert.public_key)
                .map_err(|e| CertificateCacheError::InvalidPublicKey(e.to_string()))?;

        // Verify key length (Ed25519 public keys are 32 bytes)
        if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(CertificateCacheError::InvalidPublicKey(format!(
                "Expected {} bytes, got {}",
                PUBLIC_KEY_LENGTH,
                public_key_bytes.len()
            )));
        }

        // Create Ed25519 verifying key
        let verifying_key =
            VerifyingKey::from_bytes(public_key_bytes.as_slice().try_into().map_err(|_| {
                CertificateCacheError::InvalidPublicKey("Failed to convert bytes".to_string())
            })?)
            .map_err(|e| CertificateCacheError::InvalidPublicKey(e.to_string()))?;

        // Convert to jsonwebtoken DecodingKey
        let decoding_key = DecodingKey::from_ed_der(verifying_key.as_bytes());
        let decoding_key = Arc::new(decoding_key);

        // Cache it
        self.cache.insert(parsed_kid, decoding_key.clone()).await;

        Ok(decoding_key)
    }
}

/// Error parsing key ID from JWT header
#[derive(Debug, thiserror::Error)]
pub enum KeyIdParseError {
    /// Invalid kid format (expected: org-{org_id}-client-{client_id}-cert-{cert_id})
    #[error("Invalid kid format (expected: org-{{org_id}}-client-{{client_id}}-cert-{{cert_id}})")]
    InvalidFormat,

    /// Invalid UUID in key ID component
    #[error("Invalid UUID in {0}")]
    InvalidUuid(&'static str),
}

/// Error fetching or decoding certificate
#[derive(Debug, thiserror::Error)]
pub enum CertificateCacheError {
    /// Invalid kid format
    #[error("Invalid kid: {0}")]
    InvalidKeyId(#[from] KeyIdParseError),

    /// Certificate not found in Management API
    #[error("Certificate not found")]
    CertificateNotFound,

    /// Unsupported algorithm (only EdDSA is supported)
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid public key (wrong length, format, or encoding)
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Management API request failed
    #[error("Management API error: {0}")]
    ManagementApiError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_kid() {
        let kid = "org-00000000-0000-0000-0000-000000000001-client-00000000-0000-0000-0000-000000000002-cert-00000000-0000-0000-0000-000000000003";
        let parsed = ParsedKeyId::parse(kid).unwrap();

        assert_eq!(parsed.org_id, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
        assert_eq!(
            parsed.client_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap()
        );
        assert_eq!(
            parsed.cert_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap()
        );
    }

    #[test]
    fn test_parse_invalid_format_wrong_prefix() {
        let kid = "organization-00000000-0000-0000-0000-000000000001-client-00000000-0000-0000-0000-000000000002-cert-00000000-0000-0000-0000-000000000003";
        assert!(matches!(ParsedKeyId::parse(kid), Err(KeyIdParseError::InvalidFormat)));
    }

    #[test]
    fn test_parse_invalid_uuid() {
        // Invalid UUID format (not valid hex digits)
        let kid = "org-zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz-client-00000000-0000-0000-0000-000000000002-cert-00000000-0000-0000-0000-000000000003";
        assert!(matches!(ParsedKeyId::parse(kid), Err(KeyIdParseError::InvalidUuid(_))));
    }

    #[test]
    fn test_parse_too_few_parts() {
        let kid = "org-client-cert";
        assert!(matches!(ParsedKeyId::parse(kid), Err(KeyIdParseError::InvalidFormat)));
    }
}
