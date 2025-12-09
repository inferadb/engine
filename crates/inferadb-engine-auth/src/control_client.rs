//! Control client for validating tokens and fetching metadata
//!
//! This module provides an HTTP client for communicating with InferaDB Control
//! to validate vaults, organizations, and fetch client certificates for JWT verification.
//!
//! Supports two modes:
//! - **Static mode**: Single base URL (Kubernetes service handles load balancing)
//! - **Load-balanced mode**: Client-side load balancing across discovered pod IPs

use std::{sync::Arc, time::Duration};

use reqwest::{Client as HttpClient, StatusCode};
use serde::Deserialize;

use crate::server_identity::ServerIdentity;

/// Control client for validating tokens and fetching metadata
pub struct ControlClient {
    http_client: HttpClient,
    /// Internal base URL for engine-to-control /internal/* endpoints
    /// Falls back to base_url if not set
    internal_base_url: String,
    /// Optional server identity for signing engine-to-control requests
    server_identity: Option<Arc<ServerIdentity>>,
    /// Control URL for JWT audience
    jwt_audience_url: String,
}

/// Organization information from Control
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

/// Vault information from Control
#[derive(Debug, Clone, Deserialize)]
pub struct VaultInfo {
    /// Vault Snowflake ID
    pub id: i64,
    /// Vault name
    pub name: String,
    /// Organization Snowflake ID that owns this vault
    pub organization_id: i64,
}

impl ControlClient {
    /// Create a new Control client
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL of Control (e.g., "https://api.inferadb.com")
    ///   - Without load balancing: Used directly for all requests
    ///   - With load balancing: Used as fallback and for JWT audience
    /// * `internal_base_url` - Base URL for internal /internal/* endpoints (e.g., "http://control:9091")
    ///   - If None, falls back to base_url
    /// * `timeout_ms` - Request timeout in milliseconds
    /// * `lb_client` - Optional load balancing client for discovered endpoints
    /// * `server_identity` - Optional server identity for signing engine-to-control requests
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created
    pub fn new(
        base_url: String,
        internal_base_url: Option<String>,
        timeout_ms: u64,
        _lb_client: Option<Arc<inferadb_engine_discovery::LoadBalancingClient>>,
        server_identity: Option<Arc<ServerIdentity>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(10)
            .build()?;

        let jwt_audience_url = base_url.clone();
        let internal_base_url = internal_base_url.unwrap_or_else(|| base_url.clone());
        Ok(Self { http_client, internal_base_url, server_identity, jwt_audience_url })
    }

    /// Get the internal base URL for engine-to-control /internal/* endpoints
    fn get_internal_base_url(&self) -> String {
        self.internal_base_url.clone()
    }

    /// Get authorization header for engine-to-control requests
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
    pub async fn get_organization(&self, org_id: i64) -> Result<OrganizationInfo, ControlApiError> {
        // Use internal URL for /internal/* endpoints
        let internal_url = self.get_internal_base_url();
        let url = format!("{}/internal/organizations/{}", internal_url, org_id);

        let mut request = self.http_client.get(&url);

        // Add authorization header if server identity is configured
        if let Some(auth_header) = self.get_auth_header() {
            request = request.header("Authorization", auth_header);
        }

        let response =
            request.send().await.map_err(|e| ControlApiError::RequestFailed(e.to_string()))?;

        match response.status() {
            StatusCode::OK => {
                let org = response
                    .json::<OrganizationInfo>()
                    .await
                    .map_err(|e| ControlApiError::InvalidResponse(e.to_string()))?;
                Ok(org)
            },
            StatusCode::NOT_FOUND => {
                // NOT_FOUND is expected for invalid org IDs
                Err(ControlApiError::NotFound("organization"))
            },
            status => Err(ControlApiError::UnexpectedStatus(status.as_u16())),
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
    pub async fn get_vault(&self, vault_id: i64) -> Result<VaultInfo, ControlApiError> {
        // Use internal URL for /internal/* endpoints
        let internal_url = self.get_internal_base_url();
        let url = format!("{}/internal/vaults/{}", internal_url, vault_id);

        let mut request = self.http_client.get(&url);

        // Add authorization header if server identity is configured
        if let Some(auth_header) = self.get_auth_header() {
            request = request.header("Authorization", auth_header);
        }

        let response =
            request.send().await.map_err(|e| ControlApiError::RequestFailed(e.to_string()))?;

        match response.status() {
            StatusCode::OK => {
                let vault = response
                    .json::<VaultInfo>()
                    .await
                    .map_err(|e| ControlApiError::InvalidResponse(e.to_string()))?;
                Ok(vault)
            },
            StatusCode::NOT_FOUND => {
                // NOT_FOUND is expected for invalid vault IDs
                Err(ControlApiError::NotFound("vault"))
            },
            status => Err(ControlApiError::UnexpectedStatus(status.as_u16())),
        }
    }
}

/// Errors that can occur when interacting with Control
#[derive(Debug, thiserror::Error)]
pub enum ControlApiError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    /// Invalid response from Control
    #[error("Invalid response from Control: {0}")]
    InvalidResponse(String),

    /// Resource not found
    #[error("{0} not found")]
    NotFound(&'static str),

    /// Unexpected HTTP status code
    #[error("Unexpected HTTP status: {0}")]
    UnexpectedStatus(u16),
}
