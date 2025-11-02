//! List accounts handler

use axum::{
    Json,
    extract::{Query, State},
};
use infera_types::{AccountResponse, ListAccountsResponse};
use serde::Deserialize;

use crate::{ApiError, AppState, require_admin_scope};

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
    State(state): State<AppState>,
    Query(params): Query<ListQueryParams>,
) -> Result<Json<ListAccountsResponse>, ApiError> {
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

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use infera_config::Config;
    use infera_core::{Evaluator, ipl::Schema};
    use infera_store::{MemoryBackend, RelationshipStore};
    use infera_types::Account;
    use uuid::Uuid;

    use super::*;

    fn create_test_state() -> AppState {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![]));
        let test_vault = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let evaluator = Arc::new(Evaluator::new(Arc::clone(&store), schema, None, test_vault));
        let config = Arc::new(Config::default());
        let health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState {
            evaluator,
            store,
            config,
            jwks_cache: None,
            health_tracker,
            default_vault: test_vault,
        }
    }

    fn create_admin_context() -> infera_auth::AuthContext {
        infera_auth::AuthContext {
            tenant_id: "test".to_string(),
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: infera_auth::AuthMethod::Jwt,
            scopes: vec!["inferadb.admin".to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: Uuid::nil(),
            account: Uuid::nil(),
        }
    }

    #[tokio::test]
    async fn test_list_accounts_requires_admin() {
        let state = create_test_state();
        let params = Query(ListQueryParams { limit: None });

        let result =
            list_accounts(infera_auth::extractor::OptionalAuth(None), State(state), params).await;

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
        let account1 = Account::new("Account 1".to_string());
        let account2 = Account::new("Account 2".to_string());
        state.store.create_account(account1).await.unwrap();
        state.store.create_account(account2).await.unwrap();

        let params = Query(ListQueryParams { limit: None });

        let result = list_accounts(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            State(state),
            params,
        )
        .await
        .unwrap();

        assert_eq!(result.0.accounts.len(), 2);
    }

    #[tokio::test]
    async fn test_list_accounts_with_limit() {
        let state = create_test_state();

        // Create test accounts
        for i in 0..5 {
            let account = Account::new(format!("Account {}", i));
            state.store.create_account(account).await.unwrap();
        }

        let params = Query(ListQueryParams { limit: Some(3) });

        let result = list_accounts(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            State(state),
            params,
        )
        .await
        .unwrap();

        assert_eq!(result.0.accounts.len(), 3);
    }
}
