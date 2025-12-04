//! Update vault handler

use axum::{
    Json,
    extract::{Path, State},
};
use infera_types::{UpdateVaultRequest, VaultResponse};

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::require_admin_scope,
    validation::validate_vault_name,
};

/// Update a vault
///
/// This endpoint allows administrators to update vault details.
/// Only users with the `inferadb.admin` scope can update vaults.
///
/// **Note**: Transferring a vault to a different account (changing `account` field)
/// is a sensitive operation and requires admin privileges.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.admin` scope
///
/// # Path Parameters
/// - `id`: Vault UUID
///
/// # Request Body
/// ```json
/// {
///   "name": "New Vault Name",
///   "account": "770e8400-e29b-41d4-a716-446655440000"
/// }
/// ```
///
/// # Response (200 OK)
/// ```json
/// {
///   "id": "660e8400-e29b-41d4-a716-446655440000",
///   "account": "770e8400-e29b-41d4-a716-446655440000",
///   "name": "New Vault Name",
///   "created_at": "2025-11-02T10:00:00Z",
///   "updated_at": "2025-11-02T11:00:00Z"
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing `inferadb.admin` scope
/// - 404 Not Found: Vault or new account does not exist
/// - 400 Bad Request: Invalid vault name
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn update_vault(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(vault_id): Path<i64>,
    Json(request): Json<UpdateVaultRequest>,
) -> Result<ResponseData<VaultResponse>, ApiError> {
    // Require admin scope for vault updates
    require_admin_scope(&auth.0)?;

    // Get existing vault
    let mut vault = state
        .store
        .get_vault(vault_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Vault not found".to_string()))?;

    // Update name if provided
    if let Some(new_name) = request.name {
        validate_vault_name(&new_name)?;
        vault.name = new_name;
    }

    // Update organization if provided (vault transfer)
    if let Some(new_organization) = request.organization {
        // Verify new organization exists
        state
            .store
            .get_organization(new_organization)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::UnknownTenant("New organization not found".to_string()))?;

        vault.organization = new_organization;
        tracing::info!(
            vault_id = %vault.id,
            old_organization = %vault.organization,
            new_organization = %new_organization,
            "Transferring vault to new organization"
        );
    }

    vault.updated_at = chrono::Utc::now();

    // Save to storage
    let updated_vault =
        state.store.update_vault(vault).await.map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(vault_id = %updated_vault.id, "Vault updated");

    Ok(ResponseData::new(VaultResponse::from(updated_vault), format))
}
