//! List vaults handler

use axum::extract::{Path, State};
use infera_types::{ListVaultsResponse, VaultResponse};

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_account_access,
};

/// List vaults for an account
///
/// This endpoint allows users to list vaults owned by an account.
/// Authorization rules:
/// - Administrators (with `inferadb.admin` scope) can list vaults for any account
/// - Users can only list vaults for their own account
///
/// # Authorization
/// - Requires authentication
/// - Requires either `inferadb.admin` scope OR account ownership
///
/// # Path Parameters
/// - `account_id`: Account UUID
///
/// # Response (200 OK)
/// ```json
/// {
///   "vaults": [
///     {
///       "id": "660e8400-e29b-41d4-a716-446655440000",
///       "account": "550e8400-e29b-41d4-a716-446655440000",
///       "name": "Production Vault",
///       "created_at": "2025-11-02T10:00:00Z",
///       "updated_at": "2025-11-02T10:00:00Z"
///     }
///   ]
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Not authorized to list vaults for this account
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn list_vaults(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(account_id): Path<i64>,
) -> Result<ResponseData<ListVaultsResponse>, ApiError> {
    // Check authorization (admin OR account owner)
    authorize_account_access(&auth.0, account_id)?;

    // List vaults from storage
    let vaults = state
        .store
        .list_vaults_for_account(account_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::debug!(count = vaults.len(), account_id = %account_id, "Listed vaults");

    // Convert to response
    let response =
        ListVaultsResponse { vaults: vaults.into_iter().map(VaultResponse::from).collect() };

    Ok(ResponseData::new(response, format))
}
