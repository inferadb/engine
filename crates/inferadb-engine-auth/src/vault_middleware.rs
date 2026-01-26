use std::{fmt, sync::Arc};

use async_trait::async_trait;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_engine_types::auth::AuthContext;
use tracing::{error, warn};

/// Information about a vault returned by the verifier
#[derive(Debug, Clone)]
pub struct VaultInfo {
    /// The vault's unique identifier (Snowflake ID)
    pub vault_id: i64,
    /// The organization that owns this vault (Snowflake ID)
    pub organization_id: i64,
}

/// Errors that can occur during vault verification
#[derive(Debug)]
pub enum VaultVerificationError {
    /// The vault was not found
    VaultNotFound(i64),
    /// The vault exists but belongs to a different organization
    AccountMismatch {
        /// The vault ID that was checked
        vault_id: i64,
        /// The expected organization ID
        expected_org: i64,
        /// The actual organization that owns the vault
        actual_org: i64,
    },
    /// The organization was not found
    OrganizationNotFound(i64),
    /// The organization is suspended
    OrganizationSuspended(i64),
    /// Error communicating with the verification backend (Control API or Ledger)
    ControlApiError(String),
}

impl fmt::Display for VaultVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VaultNotFound(id) => write!(f, "Vault {} not found", id),
            Self::AccountMismatch { vault_id, expected_org, actual_org } => {
                write!(
                    f,
                    "Vault {} belongs to org {} but expected org {}",
                    vault_id, actual_org, expected_org
                )
            },
            Self::OrganizationNotFound(id) => write!(f, "Organization {} not found", id),
            Self::OrganizationSuspended(id) => write!(f, "Organization {} is suspended", id),
            Self::ControlApiError(msg) => write!(f, "Verification backend error: {}", msg),
        }
    }
}

impl std::error::Error for VaultVerificationError {}

/// Trait for verifying vault ownership and organization status
///
/// This trait abstracts the verification backend, allowing different
/// implementations (e.g., Control API, Ledger-backed).
#[async_trait]
pub trait VaultVerifier: Send + Sync {
    /// Verify that a vault exists and belongs to the expected organization
    async fn verify_vault(
        &self,
        vault_id: i64,
        expected_org_id: i64,
    ) -> Result<VaultInfo, VaultVerificationError>;

    /// Verify that an organization is active
    async fn verify_organization(&self, org_id: i64) -> Result<(), VaultVerificationError>;
}

/// Ledger-backed implementation of [`VaultVerifier`].
///
/// This implementation uses the Engine's storage layer to verify vault ownership
/// and organization status. In the Ledger-based architecture, vaults and
/// organizations are stored in the distributed ledger, eliminating the need
/// for Control API calls.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use inferadb_engine_auth::vault_middleware::LedgerVaultVerifier;
///
/// let store: Arc<dyn InferaStore> = /* ... */;
/// let verifier = LedgerVaultVerifier::new(store);
///
/// // Verify vault 123 belongs to org 456
/// let info = verifier.verify_vault(123, 456).await?;
/// ```
pub struct LedgerVaultVerifier<S>
where
    S: inferadb_engine_store::VaultStore + inferadb_engine_store::OrganizationStore + ?Sized,
{
    store: Arc<S>,
}

impl<S> LedgerVaultVerifier<S>
where
    S: inferadb_engine_store::VaultStore + inferadb_engine_store::OrganizationStore + ?Sized,
{
    /// Creates a new Ledger-backed vault verifier.
    ///
    /// # Arguments
    ///
    /// * `store` - Storage backend that provides vault and organization lookup
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl<S> VaultVerifier for LedgerVaultVerifier<S>
where
    S: inferadb_engine_store::VaultStore
        + inferadb_engine_store::OrganizationStore
        + Send
        + Sync
        + ?Sized,
{
    async fn verify_vault(
        &self,
        vault_id: i64,
        expected_org_id: i64,
    ) -> Result<VaultInfo, VaultVerificationError> {
        // Fetch vault from storage
        let vault = self
            .store
            .get_vault(vault_id)
            .await
            .map_err(|e| VaultVerificationError::ControlApiError(e.to_string()))?
            .ok_or(VaultVerificationError::VaultNotFound(vault_id))?;

        // Verify organization ownership
        if vault.organization != expected_org_id {
            return Err(VaultVerificationError::AccountMismatch {
                vault_id,
                expected_org: expected_org_id,
                actual_org: vault.organization,
            });
        }

        Ok(VaultInfo { vault_id, organization_id: vault.organization })
    }

    async fn verify_organization(&self, org_id: i64) -> Result<(), VaultVerificationError> {
        // Verify organization exists in storage
        let _org = self
            .store
            .get_organization(org_id)
            .await
            .map_err(|e| VaultVerificationError::ControlApiError(e.to_string()))?
            .ok_or(VaultVerificationError::OrganizationNotFound(org_id))?;

        // Note: The Organization struct doesn't have a status field.
        // In the Ledger-based architecture, organizations that exist are assumed active.
        // Suspension is handled at the Control layer before requests reach Engine.

        Ok(())
    }
}

/// Middleware that validates vault ownership using VaultVerifier
///
/// This middleware verifies that the vault in the request belongs to the
/// authenticated organization by calling the Control API.
pub async fn control_verified_vault_middleware(
    vault_verifier: Arc<dyn VaultVerifier>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |req: Request, next: Next| {
        let verifier = vault_verifier.clone();
        Box::pin(async move {
            // Extract auth context from request extensions
            let auth_ctx = match req.extensions().get::<Arc<AuthContext>>() {
                Some(ctx) => ctx.clone(),
                None => {
                    // No auth context - let it through (auth middleware will handle)
                    return next.run(req).await;
                },
            };

            // Skip validation if vault is 0 (some endpoints don't require vault)
            if auth_ctx.vault == 0 {
                return next.run(req).await;
            }

            // Verify vault exists and belongs to organization
            match verifier.verify_vault(auth_ctx.vault, auth_ctx.organization).await {
                Ok(vault_info) => {
                    // Verify organization is active
                    if let Err(e) = verifier.verify_organization(vault_info.organization_id).await {
                        warn!(
                            vault_id = %auth_ctx.vault,
                            org_id = %vault_info.organization_id,
                            error = %e,
                            "Organization verification failed"
                        );
                        return (StatusCode::FORBIDDEN, "Organization is not active")
                            .into_response();
                    }

                    // All checks passed - continue
                    next.run(req).await
                },
                Err(e) => {
                    error!(
                        vault_id = %auth_ctx.vault,
                        organization_id = %auth_ctx.organization,
                        error = %e,
                        "Vault verification failed"
                    );

                    let (status, message) = match e {
                        VaultVerificationError::VaultNotFound(_) => {
                            (StatusCode::NOT_FOUND, "Vault not found")
                        },
                        VaultVerificationError::AccountMismatch { .. } => {
                            (StatusCode::FORBIDDEN, "Vault does not belong to this organization")
                        },
                        VaultVerificationError::OrganizationNotFound(_) => {
                            (StatusCode::NOT_FOUND, "Organization not found")
                        },
                        VaultVerificationError::OrganizationSuspended(_) => {
                            (StatusCode::FORBIDDEN, "Organization is suspended")
                        },
                        VaultVerificationError::ControlApiError(_) => {
                            (StatusCode::SERVICE_UNAVAILABLE, "Unable to verify vault")
                        },
                    };

                    (status, message).into_response()
                },
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented)]
mod tests {
    use inferadb_engine_types::{Organization, SystemConfig, Vault};

    use super::*;

    /// Mock store for testing LedgerVaultVerifier
    struct MockStore {
        vaults: std::collections::HashMap<i64, Vault>,
        organizations: std::collections::HashMap<i64, Organization>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                vaults: std::collections::HashMap::new(),
                organizations: std::collections::HashMap::new(),
            }
        }

        fn with_vault(mut self, vault: Vault) -> Self {
            self.vaults.insert(vault.id, vault);
            self
        }

        fn with_organization(mut self, org: Organization) -> Self {
            self.organizations.insert(org.id, org);
            self
        }
    }

    #[async_trait]
    impl inferadb_engine_store::VaultStore for MockStore {
        async fn create_vault(&self, _vault: Vault) -> inferadb_engine_types::StoreResult<Vault> {
            unimplemented!()
        }

        async fn get_vault(&self, id: i64) -> inferadb_engine_types::StoreResult<Option<Vault>> {
            Ok(self.vaults.get(&id).cloned())
        }

        async fn list_vaults_for_organization(
            &self,
            _organization_id: i64,
        ) -> inferadb_engine_types::StoreResult<Vec<Vault>> {
            unimplemented!()
        }

        async fn delete_vault(&self, _id: i64) -> inferadb_engine_types::StoreResult<()> {
            unimplemented!()
        }

        async fn update_vault(&self, _vault: Vault) -> inferadb_engine_types::StoreResult<Vault> {
            unimplemented!()
        }

        async fn get_system_config(
            &self,
        ) -> inferadb_engine_types::StoreResult<Option<SystemConfig>> {
            unimplemented!()
        }

        async fn set_system_config(
            &self,
            _config: SystemConfig,
        ) -> inferadb_engine_types::StoreResult<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl inferadb_engine_store::OrganizationStore for MockStore {
        async fn create_organization(
            &self,
            _organization: Organization,
        ) -> inferadb_engine_types::StoreResult<Organization> {
            unimplemented!()
        }

        async fn get_organization(
            &self,
            id: i64,
        ) -> inferadb_engine_types::StoreResult<Option<Organization>> {
            Ok(self.organizations.get(&id).cloned())
        }

        async fn list_organizations(
            &self,
            _limit: Option<usize>,
        ) -> inferadb_engine_types::StoreResult<Vec<Organization>> {
            unimplemented!()
        }

        async fn delete_organization(&self, _id: i64) -> inferadb_engine_types::StoreResult<()> {
            unimplemented!()
        }

        async fn update_organization(
            &self,
            _organization: Organization,
        ) -> inferadb_engine_types::StoreResult<Organization> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_verify_vault_success() {
        let org = Organization::new(100, "Test Org".to_string());
        let vault = Vault::new(1, 100, "Test Vault".to_string());
        let store = Arc::new(MockStore::new().with_organization(org).with_vault(vault));

        let verifier = LedgerVaultVerifier::new(store);
        let result = verifier.verify_vault(1, 100).await;

        assert!(result.is_ok());
        let info = result.expect("should succeed");
        assert_eq!(info.vault_id, 1);
        assert_eq!(info.organization_id, 100);
    }

    #[tokio::test]
    async fn test_verify_vault_not_found() {
        let store = Arc::new(MockStore::new());
        let verifier = LedgerVaultVerifier::new(store);

        let result = verifier.verify_vault(999, 100).await;

        assert!(matches!(result, Err(VaultVerificationError::VaultNotFound(999))));
    }

    #[tokio::test]
    async fn test_verify_vault_wrong_organization() {
        let vault = Vault::new(1, 200, "Test Vault".to_string()); // belongs to org 200
        let store = Arc::new(MockStore::new().with_vault(vault));

        let verifier = LedgerVaultVerifier::new(store);
        let result = verifier.verify_vault(1, 100).await; // but we claim org 100

        assert!(matches!(
            result,
            Err(VaultVerificationError::AccountMismatch {
                vault_id: 1,
                expected_org: 100,
                actual_org: 200,
            })
        ));
    }

    #[tokio::test]
    async fn test_verify_organization_success() {
        let org = Organization::new(100, "Test Org".to_string());
        let store = Arc::new(MockStore::new().with_organization(org));

        let verifier = LedgerVaultVerifier::new(store);
        let result = verifier.verify_organization(100).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_organization_not_found() {
        let store = Arc::new(MockStore::new());
        let verifier = LedgerVaultVerifier::new(store);

        let result = verifier.verify_organization(999).await;

        assert!(matches!(result, Err(VaultVerificationError::OrganizationNotFound(999))));
    }
}
