//! Get account handler

use axum::extract::{Path, State};
use infera_types::AccountResponse;

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_account_access,
};

/// Get an account by ID
///
/// This endpoint allows users to retrieve account details.
/// Authorization rules:
/// - Administrators (with `inferadb.admin` scope) can view any account
/// - Users can only view their own account
///
/// # Authorization
/// - Requires authentication
/// - Requires either `inferadb.admin` scope OR account ownership
///
/// # Path Parameters
/// - `id`: Account UUID
///
/// # Response (200 OK)
/// ```json
/// {
///   "id": "550e8400-e29b-41d4-a716-446655440000",
///   "name": "Acme Corp",
///   "created_at": "2025-11-02T10:00:00Z",
///   "updated_at": "2025-11-02T10:00:00Z"
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Not authorized to view this account
/// - 404 Not Found: Account does not exist
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn get_account(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(account_id): Path<i64>,
) -> Result<ResponseData<AccountResponse>, ApiError> {
    // Check authorization (admin OR account owner)
    authorize_account_access(&auth.0, account_id)?;

    // Get account from storage
    let account = state
        .store
        .get_account(account_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Account not found".to_string()))?;

    tracing::debug!(account_id = %account.id, account_name = %account.name, "Account retrieved");

    Ok(ResponseData::new(AccountResponse::from(account), format))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use infera_config::Config;
    use infera_const::scopes::{SCOPE_ADMIN, SCOPE_CHECK, SCOPE_WRITE};
    use infera_core::ipl::Schema;
    use infera_store::MemoryBackend;
    use infera_types::Account;

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

    fn create_user_context(account_id: i64) -> infera_types::AuthContext {
        infera_types::AuthContext {
            tenant_id: "test".to_string(),
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: infera_types::AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_CHECK.to_string(), SCOPE_WRITE.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: 0i64,
            account: account_id,
        }
    }

    #[tokio::test]
    async fn test_get_account_requires_auth() {
        let state = create_test_state();
        let account_id = 999i64;

        let result = get_account(
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
    async fn test_get_account_admin_can_view_any() {
        let state = create_test_state();

        // Create test account
        let account = Account::new(11111111111111i64, "Test Account".to_string());
        let created = state.store.create_account(account).await.unwrap();

        let result = get_account(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created.id),
        )
        .await
        .unwrap();

        assert_eq!(result.data.id, created.id);
        assert_eq!(result.data.name, "Test Account");
    }

    #[tokio::test]
    async fn test_get_account_user_can_view_own() {
        let state = create_test_state();

        // Create test account
        let account = Account::new(22222222222222i64, "My Account".to_string());
        let created = state.store.create_account(account).await.unwrap();

        let result = get_account(
            infera_auth::extractor::OptionalAuth(Some(create_user_context(created.id))),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created.id),
        )
        .await
        .unwrap();

        assert_eq!(result.data.id, created.id);
    }

    #[tokio::test]
    async fn test_get_account_user_cannot_view_other() {
        let state = create_test_state();

        // Create test account
        let account = Account::new(33333333333333i64, "Other Account".to_string());
        let created = state.store.create_account(account).await.unwrap();

        // Try to access with different account ID
        let other_account_id = 777i64;

        let result = get_account(
            infera_auth::extractor::OptionalAuth(Some(create_user_context(other_account_id))),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created.id),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Forbidden(_) => {},
            e => panic!("Expected Forbidden, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_account_not_found() {
        let state = create_test_state();
        let account_id = 666i64;

        let result = get_account(
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
