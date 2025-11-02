//! OIDC Discovery Client
//!
//! This module implements OpenID Connect Discovery (RFC 8414) for fetching
//! OAuth 2.0 server metadata.

use crate::error::AuthError;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// OpenID Connect Discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfiguration {
    /// OAuth 2.0 issuer identifier
    pub issuer: String,

    /// JWKS URI for fetching public keys
    pub jwks_uri: String,

    /// Token endpoint for token exchange
    pub token_endpoint: String,

    /// Token introspection endpoint (RFC 7662)
    pub introspection_endpoint: Option<String>,

    /// Supported signing algorithms
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// OIDC Discovery client with caching
pub struct OidcDiscoveryClient {
    http_client: reqwest::Client,
    cache: Arc<Cache<String, OidcConfiguration>>,
}

impl OidcDiscoveryClient {
    /// Create a new OIDC discovery client
    ///
    /// # Arguments
    ///
    /// * `cache_ttl` - How long to cache discovery documents (recommended: 24 hours)
    pub fn new(cache_ttl: Duration) -> Self {
        let cache = Arc::new(
            Cache::builder()
                .max_capacity(100) // Up to 100 different issuers
                .time_to_live(cache_ttl)
                .build(),
        );

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self { http_client, cache }
    }

    /// Discover OIDC configuration from issuer
    ///
    /// Fetches the OpenID Connect Discovery document from:
    /// `{issuer}/.well-known/openid-configuration`
    ///
    /// Results are cached for 24 hours to reduce load on auth servers.
    ///
    /// # Arguments
    ///
    /// * `issuer_url` - The OAuth 2.0 issuer URL (e.g., "https://auth.example.com")
    ///
    /// # Returns
    ///
    /// The OIDC configuration with JWKS URI, endpoints, and supported algorithms
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if:
    /// - Network request fails
    /// - Response is not valid JSON
    /// - Required fields are missing
    ///
    /// # Example
    ///
    /// ```no_run
    /// use infera_auth::oidc::OidcDiscoveryClient;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = OidcDiscoveryClient::new(Duration::from_secs(86400));
    /// let config = client.discover("https://auth.example.com").await?;
    /// println!("JWKS URI: {}", config.jwks_uri);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn discover(&self, issuer_url: &str) -> Result<OidcConfiguration, AuthError> {
        // Check cache first
        if let Some(cached) = self.cache.get(issuer_url).await {
            tracing::debug!(issuer = %issuer_url, "OIDC config cache hit");
            return Ok(cached);
        }

        tracing::info!(issuer = %issuer_url, "Fetching OIDC discovery document");

        // Construct well-known URL
        let discovery_url = if issuer_url.ends_with('/') {
            format!(
                "{}/.well-known/openid-configuration",
                issuer_url.trim_end_matches('/')
            )
        } else {
            format!("{}/.well-known/openid-configuration", issuer_url)
        };

        // Perform discovery and record metrics
        let result = async {
            // Fetch discovery document
            let response = self
                .http_client
                .get(&discovery_url)
                .send()
                .await
                .map_err(|e| {
                    AuthError::JwksError(format!("Failed to fetch OIDC discovery: {}", e))
                })?;

            if !response.status().is_success() {
                return Err(AuthError::JwksError(format!(
                    "OIDC discovery failed with status: {}",
                    response.status()
                )));
            }

            // Parse response
            let config: OidcConfiguration = response.json().await.map_err(|e| {
                AuthError::JwksError(format!("Failed to parse OIDC discovery response: {}", e))
            })?;

            // Validate required fields
            if config.issuer.is_empty() {
                return Err(AuthError::JwksError(
                    "OIDC discovery: missing 'issuer' field".to_string(),
                ));
            }

            if config.jwks_uri.is_empty() {
                return Err(AuthError::JwksError(
                    "OIDC discovery: missing 'jwks_uri' field".to_string(),
                ));
            }

            if config.token_endpoint.is_empty() {
                return Err(AuthError::JwksError(
                    "OIDC discovery: missing 'token_endpoint' field".to_string(),
                ));
            }

            Ok(config)
        }
        .await;

        // Record metrics
        let success = result.is_ok();
        infera_observe::metrics::record_oidc_discovery(issuer_url, success);

        match result {
            Ok(config) => {
                // Cache the result
                self.cache
                    .insert(issuer_url.to_string(), config.clone())
                    .await;

                tracing::info!(
                    issuer = %issuer_url,
                    jwks_uri = %config.jwks_uri,
                    "OIDC discovery successful"
                );

                Ok(config)
            }
            Err(e) => Err(e),
        }
    }

    /// Get cached configuration if available
    pub async fn get_cached(&self, issuer_url: &str) -> Option<OidcConfiguration> {
        self.cache.get(issuer_url).await
    }

    /// Clear the cache (useful for testing)
    pub async fn clear_cache(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_configuration_deserialize() {
        let json = r#"{
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/jwks",
            "token_endpoint": "https://auth.example.com/token",
            "introspection_endpoint": "https://auth.example.com/introspect",
            "id_token_signing_alg_values_supported": ["RS256", "EdDSA"]
        }"#;

        let config: OidcConfiguration = serde_json::from_str(json).unwrap();
        assert_eq!(config.issuer, "https://auth.example.com");
        assert_eq!(config.jwks_uri, "https://auth.example.com/jwks");
        assert_eq!(config.token_endpoint, "https://auth.example.com/token");
        assert_eq!(
            config.introspection_endpoint,
            Some("https://auth.example.com/introspect".to_string())
        );
        assert_eq!(config.id_token_signing_alg_values_supported.len(), 2);
    }

    #[test]
    fn test_oidc_configuration_optional_fields() {
        let json = r#"{
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/jwks",
            "token_endpoint": "https://auth.example.com/token"
        }"#;

        let config: OidcConfiguration = serde_json::from_str(json).unwrap();
        assert!(config.introspection_endpoint.is_none());
        assert!(config.id_token_signing_alg_values_supported.is_empty());
    }

    #[tokio::test]
    async fn test_discovery_url_construction() {
        let _client = OidcDiscoveryClient::new(Duration::from_secs(300));

        // Test with trailing slash
        let url_with_slash = "https://auth.example.com/";
        let discovery_url = if url_with_slash.ends_with('/') {
            format!(
                "{}/.well-known/openid-configuration",
                url_with_slash.trim_end_matches('/')
            )
        } else {
            format!("{}/.well-known/openid-configuration", url_with_slash)
        };
        assert_eq!(
            discovery_url,
            "https://auth.example.com/.well-known/openid-configuration"
        );

        // Test without trailing slash
        let url_without_slash = "https://auth.example.com";
        let discovery_url = if url_without_slash.ends_with('/') {
            format!(
                "{}/.well-known/openid-configuration",
                url_without_slash.trim_end_matches('/')
            )
        } else {
            format!("{}/.well-known/openid-configuration", url_without_slash)
        };
        assert_eq!(
            discovery_url,
            "https://auth.example.com/.well-known/openid-configuration"
        );
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let client = OidcDiscoveryClient::new(Duration::from_secs(300));

        // Initially empty
        assert!(
            client
                .get_cached("https://auth.example.com")
                .await
                .is_none()
        );

        // Manually insert for testing
        let config = OidcConfiguration {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            token_endpoint: "https://auth.example.com/token".to_string(),
            introspection_endpoint: None,
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        };

        client
            .cache
            .insert("https://auth.example.com".to_string(), config.clone())
            .await;

        // Should be cached now
        let cached = client.get_cached("https://auth.example.com").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().issuer, "https://auth.example.com");

        // Clear cache
        client.clear_cache().await;

        // Should be empty again
        assert!(
            client
                .get_cached("https://auth.example.com")
                .await
                .is_none()
        );
    }
}
