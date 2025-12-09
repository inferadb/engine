use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use moka::future::Cache;

use crate::{
    control_client::{ControlApiError, ControlClient, OrgStatus, OrganizationInfo, VaultInfo},
    metrics::AuthMetrics,
};

/// Trait for verifying vault and organization ownership
#[async_trait]
pub trait VaultVerifier: Send + Sync {
    /// Verify vault exists and belongs to the specified organization
    async fn verify_vault(
        &self,
        vault_id: i64,
        organization_id: i64,
    ) -> Result<VaultInfo, VaultVerificationError>;

    /// Verify organization exists and is active
    async fn verify_organization(
        &self,
        org_id: i64,
    ) -> Result<OrganizationInfo, VaultVerificationError>;
}

/// Control-based vault verifier with caching
pub struct ControlVaultVerifier {
    client: Arc<ControlClient>,
    vault_cache: Cache<i64, Arc<VaultInfo>>,
    org_cache: Cache<i64, Arc<OrganizationInfo>>,
    metrics: Option<Arc<AuthMetrics>>,
}

impl ControlVaultVerifier {
    /// Create a new Control vault verifier with caching
    pub fn new(
        client: Arc<ControlClient>,
        vault_cache_ttl: Duration,
        org_cache_ttl: Duration,
    ) -> Self {
        Self {
            client,
            vault_cache: Cache::builder()
                .time_to_live(vault_cache_ttl)
                .max_capacity(10_000)
                .build(),
            org_cache: Cache::builder().time_to_live(org_cache_ttl).max_capacity(1_000).build(),
            metrics: None,
        }
    }

    /// Create a new Control vault verifier with caching and metrics
    pub fn new_with_metrics(
        client: Arc<ControlClient>,
        vault_cache_ttl: Duration,
        org_cache_ttl: Duration,
        metrics: Arc<AuthMetrics>,
    ) -> Self {
        Self {
            client,
            vault_cache: Cache::builder()
                .time_to_live(vault_cache_ttl)
                .max_capacity(10_000)
                .build(),
            org_cache: Cache::builder().time_to_live(org_cache_ttl).max_capacity(1_000).build(),
            metrics: Some(metrics),
        }
    }

    /// Invalidate a specific vault from the cache
    ///
    /// This is called when Control notifies us that a vault has been
    /// updated or deleted. The next request will fetch fresh data from Control.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - The Snowflake ID of the vault to invalidate
    pub async fn invalidate_vault(&self, vault_id: i64) {
        self.vault_cache.invalidate(&vault_id).await;

        // Record manual invalidation metric
        if let Some(ref metrics) = self.metrics {
            metrics.record_cache_invalidation("vault", "manual");
        }

        tracing::info!(
            vault_id = %vault_id,
            event_type = "cache.invalidation",
            cache_type = "vault",
            reason = "manual",
            "Vault cache entry invalidated"
        );
    }

    /// Invalidate a specific organization from the cache
    ///
    /// This is called when Control notifies us that an organization has been
    /// updated or deleted. The next request will fetch fresh data from Control.
    ///
    /// # Arguments
    ///
    /// * `org_id` - The Snowflake ID of the organization to invalidate
    pub async fn invalidate_organization(&self, org_id: i64) {
        self.org_cache.invalidate(&org_id).await;

        // Record manual invalidation metric
        if let Some(ref metrics) = self.metrics {
            metrics.record_cache_invalidation("organization", "manual");
        }

        tracing::info!(
            org_id = %org_id,
            event_type = "cache.invalidation",
            cache_type = "organization",
            reason = "manual",
            "Organization cache entry invalidated"
        );
    }

    /// Clear all caches (vaults and organizations)
    ///
    /// This is a nuclear option for troubleshooting or after major Control changes.
    /// Use sparingly as it will cause a temporary spike in Control requests.
    pub async fn clear_all_caches(&self) {
        let vault_count = self.vault_cache.entry_count();
        let org_count = self.org_cache.entry_count();

        self.vault_cache.invalidate_all();
        self.org_cache.invalidate_all();

        // Record manual invalidation metric
        if let Some(ref metrics) = self.metrics {
            metrics.record_cache_invalidation("all", "manual");
        }

        tracing::warn!(
            vault_cache_entries = vault_count,
            org_cache_entries = org_count,
            event_type = "cache.invalidation",
            cache_type = "all",
            reason = "manual",
            "All caches cleared"
        );
    }
}

#[async_trait]
impl VaultVerifier for ControlVaultVerifier {
    async fn verify_vault(
        &self,
        vault_id: i64,
        organization_id: i64,
    ) -> Result<VaultInfo, VaultVerificationError> {
        // Check cache first
        if let Some(cached) = self.vault_cache.get(&vault_id).await {
            // Record cache hit
            if let Some(ref metrics) = self.metrics {
                metrics.record_cache_hit("vault");
            }

            if cached.organization_id == organization_id {
                return Ok((*cached).clone());
            } else {
                return Err(VaultVerificationError::AccountMismatch {
                    vault_id,
                    expected: organization_id,
                    actual: cached.organization_id,
                });
            }
        }

        // Record cache miss
        if let Some(ref metrics) = self.metrics {
            metrics.record_cache_miss("vault");
        }

        // Fetch from Control
        let vault_info = self.client.get_vault(vault_id).await.map_err(|e| {
            // Record API call status
            if let Some(ref metrics) = self.metrics {
                let status = match &e {
                    ControlApiError::NotFound(_) => 404,
                    ControlApiError::UnexpectedStatus(code) => *code,
                    _ => 500,
                };
                metrics.record_control_api_call("get_vault", status);
            }

            match e {
                ControlApiError::NotFound(_) => VaultVerificationError::VaultNotFound(vault_id),
                e => VaultVerificationError::ControlApiError(e.to_string()),
            }
        })?;

        // Record successful API call
        if let Some(ref metrics) = self.metrics {
            metrics.record_control_api_call("get_vault", 200);
        }

        // Verify account ownership
        if vault_info.organization_id != organization_id {
            return Err(VaultVerificationError::AccountMismatch {
                vault_id,
                expected: organization_id,
                actual: vault_info.organization_id,
            });
        }

        // Cache and return
        self.vault_cache.insert(vault_id, Arc::new(vault_info.clone())).await;
        Ok(vault_info)
    }

    async fn verify_organization(
        &self,
        org_id: i64,
    ) -> Result<OrganizationInfo, VaultVerificationError> {
        // Check cache first
        if let Some(cached) = self.org_cache.get(&org_id).await {
            // Record cache hit
            if let Some(ref metrics) = self.metrics {
                metrics.record_cache_hit("organization");
            }

            if cached.status == OrgStatus::Active {
                return Ok((*cached).clone());
            } else {
                return Err(VaultVerificationError::OrganizationSuspended(org_id));
            }
        }

        // Record cache miss
        if let Some(ref metrics) = self.metrics {
            metrics.record_cache_miss("organization");
        }

        // Fetch from Control
        let org_info = self.client.get_organization(org_id).await.map_err(|e| {
            // Record API call status
            if let Some(ref metrics) = self.metrics {
                let status = match &e {
                    ControlApiError::NotFound(_) => 404,
                    ControlApiError::UnexpectedStatus(code) => *code,
                    _ => 500,
                };
                metrics.record_control_api_call("get_organization", status);
            }

            match e {
                ControlApiError::NotFound(_) => {
                    VaultVerificationError::OrganizationNotFound(org_id)
                },
                e => VaultVerificationError::ControlApiError(e.to_string()),
            }
        })?;

        // Record successful API call
        if let Some(ref metrics) = self.metrics {
            metrics.record_control_api_call("get_organization", 200);
        }

        // Check status
        if org_info.status != OrgStatus::Active {
            return Err(VaultVerificationError::OrganizationSuspended(org_id));
        }

        // Cache and return
        self.org_cache.insert(org_id, Arc::new(org_info.clone())).await;
        Ok(org_info)
    }
}

/// No-op verifier for when auth is disabled
pub struct NoOpVaultVerifier;

#[async_trait]
impl VaultVerifier for NoOpVaultVerifier {
    async fn verify_vault(
        &self,
        vault_id: i64,
        organization_id: i64,
    ) -> Result<VaultInfo, VaultVerificationError> {
        // Create dummy vault info without verification
        Ok(VaultInfo { id: vault_id, name: "unverified".to_string(), organization_id })
    }

    async fn verify_organization(
        &self,
        org_id: i64,
    ) -> Result<OrganizationInfo, VaultVerificationError> {
        // Create dummy org info without verification
        Ok(OrganizationInfo {
            id: org_id,
            name: "unverified".to_string(),
            status: OrgStatus::Active,
        })
    }
}

/// Errors that can occur during vault verification
#[derive(Debug, thiserror::Error)]
pub enum VaultVerificationError {
    /// Vault was not found in Control
    #[error("Vault {0} not found")]
    VaultNotFound(i64),

    /// Organization was not found in Control
    #[error("Organization {0} not found")]
    OrganizationNotFound(i64),

    /// Organization is suspended and cannot be used
    #[error("Organization {0} is suspended")]
    OrganizationSuspended(i64),

    /// Vault does not belong to the expected account
    #[error("Account mismatch for vault {vault_id}: expected {expected}, got {actual}")]
    AccountMismatch {
        /// The vault ID being verified
        vault_id: i64,
        /// The expected account ID
        expected: i64,
        /// The actual account ID
        actual: i64,
    },

    /// Error communicating with Control
    #[error("Control API error: {0}")]
    ControlApiError(String),
}
