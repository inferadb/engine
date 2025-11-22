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
/// 3. Verifies organization owns the vault
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
/// - Organization does not own the vault
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
    if auth.vault == 0 {
        tracing::warn!(
            tenant_id = %auth.organization,
            client_id = %auth.client_id,
            "Vault access denied: zero ID detected"
        );
        return Err(ApiError::Forbidden("Invalid vault: vault ID cannot be zero".to_string()));
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
                tenant_id = %auth.organization,
                "Vault does not exist"
            );
            ApiError::Forbidden("Vault does not exist".to_string())
        })?;

    // Verify organization owns the vault
    if vault.organization != auth.organization {
        tracing::warn!(
            vault = %auth.vault,
            vault_organization = %vault.organization,
            auth_organization = %auth.organization,
            tenant_id = %auth.organization,
            "Organization does not own vault"
        );
        return Err(ApiError::Forbidden(
            "Organization does not have access to this vault".to_string(),
        ));
    }

    // Log successful validation
    tracing::debug!(
        tenant_id = %auth.organization,
        vault = %auth.vault,
        organization = %auth.organization,
        client_id = %auth.client_id,
        "Vault access validated (with database verification)"
    );

    Ok(())
}
