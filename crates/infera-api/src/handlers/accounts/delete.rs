//! Delete account handler

use axum::{
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    ApiError, AppState, content_negotiation::AcceptHeader,
    handlers::utils::auth::require_admin_scope,
};

/// Delete an account
///
/// This endpoint allows administrators to delete accounts.
/// Only users with the `inferadb.admin` scope can delete accounts.
///
/// **WARNING**: Deleting an account will cascade delete:
/// - All vaults owned by the account
/// - All relationships in those vaults
///
/// This operation is irreversible.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.admin` scope
///
/// # Path Parameters
/// - `id`: Account UUID
///
/// # Response
/// - 204 No Content: Account deleted successfully
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing `inferadb.admin` scope
/// - 404 Not Found: Account does not exist
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn delete_account(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(_format): AcceptHeader,
    State(state): State<AppState>,
    Path(account_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    // Require admin scope
    require_admin_scope(&auth.0)?;

    // Verify account exists first (better error message for 404)
    let account = state
        .store
        .get_account(account_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Account not found".to_string()))?;

    tracing::info!(
        account_id = %account.id,
        account_name = %account.name,
        "Deleting account (will cascade to vaults and relationships)"
    );

    // Delete account (cascades to vaults and relationships)
    state.store.delete_account(account_id).await.map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(account_id = %account_id, "Account deleted");

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use infera_config::Config;
    use infera_const::scopes::SCOPE_ADMIN;
    use infera_core::ipl::Schema;
    use infera_store::MemoryBackend;
    use infera_types::{Account, Vault};

    use super::*;
    use crate::content_negotiation::ResponseFormat;

    fn create_test_state() -> AppState {
        let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![]));
        let test_vault = 1i64;
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::new(
            store,
            schema,
            None, // No WASM host for tests
            config,
            None, // No JWKS cache for tests
            test_vault,
            0i64,
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
            vault: 0i64,
            account: 0i64,
        }
    }

    #[tokio::test]
    async fn test_delete_account_requires_admin() {
        let state = create_test_state();
        let account_id = 999i64;

        let result = delete_account(
            infera_auth::extractor::OptionalAuth(None),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(account_id),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Unauthorized(_) => {},
            e => panic!("Expected Unauthorized, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_delete_account_success() {
        let state = create_test_state();

        // Create test account
        let account = Account::new(13131313131313i64, "Test Account".to_string());
        let created = state.store.create_account(account).await.unwrap();

        let result = delete_account(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state.clone()),
            Path(created.id),
        )
        .await
        .unwrap();

        assert_eq!(result, StatusCode::NO_CONTENT);

        // Verify it's actually deleted
        let retrieved = state.store.get_account(created.id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_delete_account_cascades_to_vaults() {
        let state = create_test_state();

        // Create test account
        let account = Account::new(14141414141414i64, "Test Account".to_string());
        let created_account = state.store.create_account(account).await.unwrap();

        // Create vault for this account
        let vault = Vault::new(15151515151515i64, created_account.id, "Test Vault".to_string());
        let created_vault = state.store.create_vault(vault).await.unwrap();

        // Delete account
        delete_account(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state.clone()),
            Path(created_account.id),
        )
        .await
        .unwrap();

        // Verify vault is also deleted (cascade)
        let retrieved_vault = state.store.get_vault(created_vault.id).await.unwrap();
        assert!(retrieved_vault.is_none(), "Vault should be cascade deleted");
    }

    #[tokio::test]
    async fn test_delete_account_not_found() {
        let state = create_test_state();
        let account_id = 888i64;

        let result = delete_account(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(account_id),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::UnknownTenant(_) => {},
            e => panic!("Expected UnknownTenant, got {:?}", e),
        }
    }
}
