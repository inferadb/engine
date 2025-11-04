//! Update account handler

use axum::{
    Json,
    extract::{Path, State},
};
use infera_types::{AccountResponse, UpdateAccountRequest};
use uuid::Uuid;

use crate::{
    ApiError, AppState, handlers::utils::auth::require_admin_scope,
    validation::validate_account_name,
};

/// Update an account
///
/// This endpoint allows administrators to update account details.
/// Only users with the `inferadb.admin` scope can update accounts.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.admin` scope
///
/// # Path Parameters
/// - `id`: Account UUID
///
/// # Request Body
/// ```json
/// {
///   "name": "New Account Name"
/// }
/// ```
///
/// # Response (200 OK)
/// ```json
/// {
///   "id": "550e8400-e29b-41d4-a716-446655440000",
///   "name": "New Account Name",
///   "created_at": "2025-11-02T10:00:00Z",
///   "updated_at": "2025-11-02T11:00:00Z"
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing `inferadb.admin` scope
/// - 404 Not Found: Account does not exist
/// - 400 Bad Request: Invalid account name
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn update_account(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Path(account_id): Path<Uuid>,
    Json(request): Json<UpdateAccountRequest>,
) -> Result<Json<AccountResponse>, ApiError> {
    // Require admin scope
    require_admin_scope(&auth.0)?;

    // Validate new name
    validate_account_name(&request.name)?;

    // Get existing account
    let mut account = state
        .store
        .get_account(account_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Account not found".to_string()))?;

    // Update fields
    account.name = request.name;
    account.updated_at = chrono::Utc::now();

    // Save to storage
    let updated_account =
        state.store.update_account(account).await.map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(
        account_id = %updated_account.id,
        new_name = %updated_account.name,
        "Account updated"
    );

    Ok(Json(AccountResponse::from(updated_account)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use infera_config::Config;
    use infera_const::scopes::SCOPE_ADMIN;
    use infera_core::ipl::Schema;
    use infera_store::MemoryBackend;
    use infera_types::Account;

    use super::*;

    fn create_test_state() -> AppState {
        let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![]));
        let test_vault = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::new(
            store,
            schema,
            None, // No WASM host for tests
            config,
            None, // No JWKS cache for tests
            test_vault,
            Uuid::nil(),
        )
    }

    fn create_admin_context() -> infera_types::AuthContext {
        infera_types::AuthContext {
            tenant_id: "test".to_string(),
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: infera_types::AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_ADMIN.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: Uuid::nil(),
            account: Uuid::nil(),
        }
    }

    #[tokio::test]
    async fn test_update_account_requires_admin() {
        let state = create_test_state();
        let account_id = Uuid::new_v4();
        let request = UpdateAccountRequest { name: "New Name".to_string() };

        let result = update_account(
            infera_auth::extractor::OptionalAuth(None),
            State(state),
            Path(account_id),
            Json(request),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Unauthorized(_) => {},
            e => panic!("Expected Unauthorized, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_update_account_success() {
        let state = create_test_state();

        // Create test account
        let account = Account::new("Old Name".to_string());
        let created = state.store.create_account(account).await.unwrap();

        let request = UpdateAccountRequest { name: "New Name".to_string() };

        let result = update_account(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            State(state.clone()),
            Path(created.id),
            Json(request),
        )
        .await
        .unwrap();

        assert_eq!(result.0.name, "New Name");
        assert_eq!(result.0.id, created.id);

        // Verify it's actually updated in storage
        let stored = state.store.get_account(created.id).await.unwrap().unwrap();
        assert_eq!(stored.name, "New Name");
    }

    #[tokio::test]
    async fn test_update_account_not_found() {
        let state = create_test_state();
        let account_id = Uuid::new_v4();
        let request = UpdateAccountRequest { name: "New Name".to_string() };

        let result = update_account(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            State(state),
            Path(account_id),
            Json(request),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::UnknownTenant(_) => {},
            e => panic!("Expected UnknownTenant, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_update_account_validates_name() {
        let state = create_test_state();

        // Create test account
        let account = Account::new("Old Name".to_string());
        let created = state.store.create_account(account).await.unwrap();

        let request = UpdateAccountRequest { name: "".to_string() };

        let result = update_account(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            State(state),
            Path(created.id),
            Json(request),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequest(msg) => {
                assert!(msg.contains("Account name cannot be empty"));
            },
            e => panic!("Expected InvalidRequest, got {:?}", e),
        }
    }
}
