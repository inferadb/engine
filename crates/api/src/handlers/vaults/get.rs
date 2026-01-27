//! Get vault handler

use axum::extract::{Path, State};
use inferadb_engine_types::VaultResponse;

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_organization_access,
};

/// Get a vault by ID
///
/// This endpoint allows users to retrieve vault details.
/// Authorization rules:
/// - Administrators (with `inferadb.admin` scope) can view any vault
/// - Users can only view vaults owned by their account
///
/// # Authorization
/// - Requires authentication
/// - Requires either `inferadb.admin` scope OR vault's account ownership
///
/// # Path Parameters
/// - `id`: Vault UUID
///
/// # Response (200 OK)
/// ```json
/// {
///   "id": "660e8400-e29b-41d4-a716-446655440000",
///   "account": "550e8400-e29b-41d4-a716-446655440000",
///   "name": "Production Vault",
///   "created_at": "2025-11-02T10:00:00Z",
///   "updated_at": "2025-11-02T10:00:00Z"
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Not authorized to view this vault
/// - 404 Not Found: Vault does not exist
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn get_vault(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(vault_id): Path<i64>,
) -> Result<ResponseData<VaultResponse>, ApiError> {
    // Get vault from storage
    let vault = state
        .store
        .get_vault(vault_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Vault not found".to_string()))?;

    // Check authorization (admin OR vault's organization owner)
    authorize_organization_access(&auth.0, vault.organization)?;

    tracing::debug!(vault_id = %vault.id, vault_name = %vault.name, "Vault retrieved");

    Ok(ResponseData::new(VaultResponse::from(vault), format))
}
