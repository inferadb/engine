//! Delete vault handler

use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    ApiError, AppState, content_negotiation::AcceptHeader,
    handlers::utils::auth::authorize_account_access,
};

/// Delete a vault
///
/// This endpoint allows users to delete vaults they own.
/// Authorization rules:
/// - Administrators (with `inferadb.admin` scope) can delete any vault
/// - Users can only delete vaults owned by their account
///
/// **WARNING**: Deleting a vault will cascade delete all relationships in that vault.
/// This operation is irreversible.
///
/// # Authorization
/// - Requires authentication
/// - Requires either `inferadb.admin` scope OR vault's account ownership
///
/// # Path Parameters
/// - `id`: Vault UUID
///
/// # Response
/// - 204 No Content: Vault deleted successfully
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Not authorized to delete this vault
/// - 404 Not Found: Vault does not exist
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn delete_vault(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(_format): AcceptHeader,
    State(state): State<AppState>,
    Path(vault_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // Get vault first to check ownership
    let vault = state
        .store
        .get_vault(vault_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Vault not found".to_string()))?;

    // Check authorization (admin OR vault's account owner)
    authorize_account_access(&auth.0, vault.account)?;

    tracing::info!(
        vault_id = %vault.id,
        vault_name = %vault.name,
        account_id = %vault.account,
        "Deleting vault (will cascade to relationships)"
    );

    // Delete vault (cascades to relationships)
    state.store.delete_vault(vault_id).await.map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(vault_id = %vault_id, "Vault deleted");

    Ok(StatusCode::NO_CONTENT)
}
