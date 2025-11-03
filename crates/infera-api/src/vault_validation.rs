//! Vault validation with database verification
//!
//! This module provides comprehensive vault access validation that includes
//! database checks to verify vault existence and ownership.

use infera_store::VaultStore;
use infera_types::AuthContext;

use crate::{ApiError, Result};

/// Validate vault access with database verification
///
/// This function performs comprehensive vault-level access validation:
/// 1. Ensures vault UUID is not nil
/// 2. Verifies vault exists in database
/// 3. Verifies account owns the vault
/// 4. Logs vault access for audit purposes
///
/// # Arguments
///
/// * `auth` - The authenticated context containing vault information
/// * `vault_store` - The vault store for database lookups
///
/// # Errors
///
/// Returns `ApiError` if:
/// - Vault UUID is nil
/// - Vault does not exist in database
/// - Account does not own the vault
/// - Database error occurs
///
/// # Example
///
/// ```rust,ignore
/// use infera_api::vault_validation::validate_vault_access_with_store;
///
/// let result = validate_vault_access_with_store(&auth, &vault_store).await?;
/// ```
pub async fn validate_vault_access_with_store(
    auth: &AuthContext,
    vault_store: &dyn VaultStore,
) -> Result<()> {
    // Basic validation first
    if auth.vault.is_nil() {
        tracing::warn!(
            tenant_id = %auth.tenant_id,
            client_id = %auth.client_id,
            "Vault access denied: nil UUID detected"
        );
        return Err(ApiError::Forbidden("Invalid vault: vault UUID cannot be nil".to_string()));
    }

    // Verify vault exists in database
    let vault = vault_store
        .get_vault(auth.vault)
        .await
        .map_err(|e| {
            tracing::error!(
                vault = %auth.vault,
                error = %e,
                "Failed to fetch vault from database"
            );
            ApiError::Internal(format!("Failed to verify vault: {}", e))
        })?
        .ok_or_else(|| {
            tracing::warn!(
                vault = %auth.vault,
                tenant_id = %auth.tenant_id,
                "Vault does not exist"
            );
            ApiError::Forbidden("Vault does not exist".to_string())
        })?;

    // Verify account owns the vault
    if vault.account != auth.account {
        tracing::warn!(
            vault = %auth.vault,
            vault_account = %vault.account,
            auth_account = %auth.account,
            tenant_id = %auth.tenant_id,
            "Account does not own vault"
        );
        return Err(ApiError::Forbidden("Account does not have access to this vault".to_string()));
    }

    // Log successful validation
    tracing::debug!(
        tenant_id = %auth.tenant_id,
        vault = %auth.vault,
        account = %auth.account,
        client_id = %auth.client_id,
        "Vault access validated (with database verification)"
    );

    Ok(())
}
