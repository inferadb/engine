//! Management API client for validating tokens and fetching metadata
//!
//! This module provides an HTTP client for communicating with the InferaDB Management API
//! to validate vaults, organizations, and fetch client certificates for JWT verification.
//!
//! Supports two modes:
//! - **Static mode**: Single base URL (Kubernetes service handles load balancing)
//! - **Load-balanced mode**: Client-side load balancing across discovered pod IPs

use std::{sync::Arc, time::Duration};

use reqwest::{Client as HttpClient, StatusCode};
use serde::Deserialize;

use crate::server_identity::ServerIdentity;

/// Management API client for validating tokens and fetching metadata
pub struct ManagementClient {
    http_client: HttpClient,
    /// Static base URL for public endpoints (used when lb_client is None)
    base_url: String,
    /// Internal base URL for server-to-server /internal/* endpoints
    /// Falls back to base_url if not set
    internal_base_url: String,
    /// Optional load balancing client for discovered endpoints
    lb_client: Option<Arc<infera_discovery::LoadBalancingClient>>,
    /// Optional server identity for signing server-to-management requests
    server_identity: Option<Arc<ServerIdentity>>,
    /// Management API URL for JWT audience
    jwt_audience_url: String,
}

/// Organization information from management API
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationInfo {
    /// Organization Snowflake ID
    pub id: i64,
    /// Organization name
    pub name: String,
    /// Organization status
    pub status: OrgStatus,
}

/// Organization status
#[derive(Debug, Clone, serde::Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrgStatus {
    /// Organization is active
    Active,
    /// Organization is suspended
    Suspended,
    /// Organization is deleted
    Deleted,
}

/// Vault information from management API
#[derive(Debug, Clone, Deserialize)]
pub struct VaultInfo {
    /// Vault Snowflake ID
    pub id: i64,
    /// Vault name
    pub name: String,
    /// Organization Snowflake ID that owns this vault
    pub organization_id: i64,
}

impl ManagementClient {
    /// Create a new management API client
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL of the management API (e.g., "https://api.inferadb.com")
    ///   - Without load balancing: Used directly for all requests
    ///   - With load balancing: Used as fallback and for JWT audience
    /// * `internal_base_url` - Base URL for internal /internal/* endpoints (e.g., "http://management-api:9091")
    ///   - If None, falls back to base_url
    /// * `timeout_ms` - Request timeout in milliseconds
    /// * `lb_client` - Optional load balancing client for discovered endpoints
    /// * `server_identity` - Optional server identity for signing server-to-management requests
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created
    pub fn new(
        base_url: String,
        internal_base_url: Option<String>,
        timeout_ms: u64,
        lb_client: Option<Arc<infera_discovery::LoadBalancingClient>>,
        server_identity: Option<Arc<ServerIdentity>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(10)
            .build()?;

        let jwt_audience_url = base_url.clone();
        let internal_base_url = internal_base_url.unwrap_or_else(|| base_url.clone());
        Ok(Self { http_client, base_url, internal_base_url, lb_client, server_identity, jwt_audience_url })
    }

    /// Get the base URL for public endpoints (either from load balancer or static config)
    fn get_base_url(&self) -> String {
        if let Some(ref lb) = self.lb_client {
            // Try to get from load balancer, fall back to static URL on error
            lb.get_next_healthy_endpoint().unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    fallback_url = %self.base_url,
                    "Failed to get endpoint from load balancer, using fallback"
                );
                self.base_url.clone()
            })
        } else {
            // Static mode
            self.base_url.clone()
        }
    }

    /// Get the internal base URL for server-to-server /internal/* endpoints
    /// This is always static (no load balancing) as internal endpoints are on a separate port
    fn get_internal_base_url(&self) -> String {
        self.internal_base_url.clone()
    }

    /// Mark a request as successful (for load balancer health tracking)
    fn mark_request_success(&self, url: &str) {
        if let Some(ref lb) = self.lb_client {
            lb.mark_success(url);
        }
    }

    /// Mark a request as failed (for load balancer health tracking)
    fn mark_request_failure(&self, url: &str) {
        if let Some(ref lb) = self.lb_client {
            lb.mark_failure(url);
        }
    }

    /// Get authorization header for server-to-management requests
    ///
    /// Returns a JWT signed by the server's identity if configured,
    /// otherwise returns None (request will be unauthenticated)
    ///
    /// Uses the stable `jwt_audience_url` (not load-balanced endpoint) for JWT audience claim
    fn get_auth_header(&self) -> Option<String> {
        self.server_identity.as_ref().and_then(|identity| {
            identity.sign_jwt(&self.jwt_audience_url).ok().map(|jwt| format!("Bearer {}", jwt))
        })
    }

    /// Fetch organization details
    ///
    /// # Arguments
    ///
    /// * `org_id` - Organization UUID
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The organization is not found
    /// - The response cannot be parsed
    pub async fn get_organization(
        &self,
        org_id: i64,
    ) -> Result<OrganizationInfo, ManagementApiError> {
        // Use internal URL for /internal/* endpoints
        let internal_url = self.get_internal_base_url();
        let url = format!("{}/internal/organizations/{}", internal_url, org_id);

        let mut request = self.http_client.get(&url);

        // Add authorization header if server identity is configured
        if let Some(auth_header) = self.get_auth_header() {
            request = request.header("Authorization", auth_header);
        }

        let response = request.send().await.map_err(|e| {
            ManagementApiError::RequestFailed(e.to_string())
        })?;

        match response.status() {
            StatusCode::OK => {
                let org = response.json::<OrganizationInfo>().await.map_err(|e| {
                    ManagementApiError::InvalidResponse(e.to_string())
                })?;
                Ok(org)
            },
            StatusCode::NOT_FOUND => {
                // NOT_FOUND is expected for invalid org IDs
                Err(ManagementApiError::NotFound("organization"))
            },
            status => {
                Err(ManagementApiError::UnexpectedStatus(status.as_u16()))
            },
        }
    }

    /// Fetch vault details
    ///
    /// # Arguments
    ///
    /// * `vault_id` - Vault UUID
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The vault is not found
    /// - The response cannot be parsed
    pub async fn get_vault(&self, vault_id: i64) -> Result<VaultInfo, ManagementApiError> {
        // Use internal URL for /internal/* endpoints
        let internal_url = self.get_internal_base_url();
        let url = format!("{}/internal/vaults/{}", internal_url, vault_id);

        let mut request = self.http_client.get(&url);

        // Add authorization header if server identity is configured
        if let Some(auth_header) = self.get_auth_header() {
            request = request.header("Authorization", auth_header);
        }

        let response = request.send().await.map_err(|e| {
            ManagementApiError::RequestFailed(e.to_string())
        })?;

        match response.status() {
            StatusCode::OK => {
                let vault = response.json::<VaultInfo>().await.map_err(|e| {
                    ManagementApiError::InvalidResponse(e.to_string())
                })?;
                Ok(vault)
            },
            StatusCode::NOT_FOUND => {
                // NOT_FOUND is expected for invalid vault IDs
                Err(ManagementApiError::NotFound("vault"))
            },
            status => {
                Err(ManagementApiError::UnexpectedStatus(status.as_u16()))
            },
        }
    }
}

/// Errors that can occur when interacting with the Management API
#[derive(Debug, thiserror::Error)]
pub enum ManagementApiError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    /// Invalid response from management API
    #[error("Invalid response from management API: {0}")]
    InvalidResponse(String),

    /// Resource not found
    #[error("{0} not found")]
    NotFound(&'static str),

    /// Unexpected HTTP status code
    #[error("Unexpected HTTP status: {0}")]
    UnexpectedStatus(u16),
}
