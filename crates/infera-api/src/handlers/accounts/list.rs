//! List accounts handler

use axum::extract::{Query, State};
use infera_types::{AccountResponse, ListAccountsResponse};
use serde::Deserialize;

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::require_admin_scope,
};

/// Query parameters for listing accounts
#[derive(Debug, Deserialize)]
pub struct ListQueryParams {
    /// Optional limit on number of accounts to return
    pub limit: Option<usize>,
}

/// List all accounts
///
/// This endpoint allows administrators to list all accounts in the system.
/// Only users with the `inferadb.admin` scope can list accounts.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.admin` scope
///
/// # Query Parameters
/// - `limit` (optional): Maximum number of accounts to return
///
/// # Response (200 OK)
/// ```json
/// {
///   "accounts": [
///     {
///       "id": "550e8400-e29b-41d4-a716-446655440000",
///       "name": "Acme Corp",
///       "created_at": "2025-11-02T10:00:00Z",
///       "updated_at": "2025-11-02T10:00:00Z"
///     }
///   ]
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing `inferadb.admin` scope
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn list_accounts(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Query(params): Query<ListQueryParams>,
) -> Result<ResponseData<ListAccountsResponse>, ApiError> {
    // Require admin scope
    require_admin_scope(&auth.0)?;

    // List accounts from storage
    let accounts = state
        .store
        .list_accounts(params.limit)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::debug!(count = accounts.len(), "Listed accounts");

    // Convert to response
    let response = ListAccountsResponse {
        accounts: accounts.into_iter().map(AccountResponse::from).collect(),
    };

    Ok(ResponseData::new(response, format))
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
    async fn test_list_accounts_requires_admin() {
        let state = create_test_state();
        let params = Query(ListQueryParams { limit: None });

        let result = list_accounts(
            infera_auth::extractor::OptionalAuth(None),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            params,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Unauthorized(_) => {},
            e => panic!("Expected Unauthorized, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_list_accounts_success() {
        let state = create_test_state();

        // Create test accounts
        let account1 = Account::new(66666666666666i64, "Account 1".to_string());
        let account2 = Account::new(77777777777777i64, "Account 2".to_string());
        state.store.create_account(account1).await.unwrap();
        state.store.create_account(account2).await.unwrap();

        let params = Query(ListQueryParams { limit: None });

        let result = list_accounts(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            params,
        )
        .await
        .unwrap();

        assert_eq!(result.data.accounts.len(), 2);
    }

    #[tokio::test]
    async fn test_list_accounts_with_limit() {
        let state = create_test_state();

        // Create test accounts
        for i in 0..5 {
            let account = Account::new(i as i64, format!("Account {}", i));
            state.store.create_account(account).await.unwrap();
        }

        let params = Query(ListQueryParams { limit: Some(3) });

        let result = list_accounts(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            params,
        )
        .await
        .unwrap();

        assert_eq!(result.data.accounts.len(), 3);
    }
}
