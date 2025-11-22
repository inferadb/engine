//! Management API client for validating tokens and fetching metadata
//!
//! This module provides an HTTP client for communicating with the InferaDB Management API
//! to validate vaults, organizations, and fetch client certificates for JWT verification.

use std::time::Duration;

use reqwest::{Client as HttpClient, StatusCode};
use serde::Deserialize;

/// Management API client for validating tokens and fetching metadata
pub struct ManagementClient {
    http_client: HttpClient,
    base_url: String,
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
    /// * `timeout_ms` - Request timeout in milliseconds
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created
    pub fn new(base_url: String, timeout_ms: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(10)
            .build()?;

        Ok(Self { http_client, base_url })
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
        let url = format!("{}/v1/organizations/{}", self.base_url, org_id);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| ManagementApiError::RequestFailed(e.to_string()))?;

        match response.status() {
            StatusCode::OK => {
                let org = response
                    .json::<OrganizationInfo>()
                    .await
                    .map_err(|e| ManagementApiError::InvalidResponse(e.to_string()))?;
                Ok(org)
            },
            StatusCode::NOT_FOUND => Err(ManagementApiError::NotFound("organization")),
            status => Err(ManagementApiError::UnexpectedStatus(status.as_u16())),
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
        let url = format!("{}/v1/vaults/{}", self.base_url, vault_id);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| ManagementApiError::RequestFailed(e.to_string()))?;

        match response.status() {
            StatusCode::OK => {
                let vault = response
                    .json::<VaultInfo>()
                    .await
                    .map_err(|e| ManagementApiError::InvalidResponse(e.to_string()))?;
                Ok(vault)
            },
            StatusCode::NOT_FOUND => Err(ManagementApiError::NotFound("vault")),
            status => Err(ManagementApiError::UnexpectedStatus(status.as_u16())),
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
