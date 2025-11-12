//! Create account handler

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use infera_types::{Account, AccountResponse, CreateAccountRequest};

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::require_admin_scope,
    validation::validate_account_name,
};

/// Create a new account
///
/// This endpoint allows administrators to create new accounts.
/// Only users with the `inferadb.admin` scope can create accounts.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.admin` scope
///
/// # Request Body
/// ```json
/// {
///   "name": "Acme Corp"
/// }
/// ```
///
/// # Response (201 Created)
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
/// - 403 Forbidden: Missing `inferadb.admin` scope
/// - 400 Bad Request: Invalid account name
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn create_account(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    axum::Json(request): axum::Json<CreateAccountRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Require admin scope
    require_admin_scope(&auth.0)?;

    // Validate account name
    validate_account_name(&request.name)?;

    // Create account with new UUID
    let account = Account::new(request.name);

    // Store in database
    let created_account =
        state.store.create_account(account).await.map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(
        account_id = %created_account.id,
        account_name = %created_account.name,
        "Account created"
    );

    // Convert to response and return 201 Created
    Ok((StatusCode::CREATED, ResponseData::new(AccountResponse::from(created_account), format)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use infera_config::Config;
    use infera_const::scopes::SCOPE_ADMIN;
    use infera_core::ipl::Schema;
    use infera_store::MemoryBackend;
    use infera_types::AuthMethod;
    use uuid::Uuid;

    use super::*;
    use crate::{AppState, content_negotiation::ResponseFormat};

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

    #[tokio::test]
    async fn test_create_account_requires_auth() {
        let state = create_test_state();

        let request = CreateAccountRequest { name: "Test Account".to_string() };

        let result = create_account(
            infera_auth::extractor::OptionalAuth(None),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        match result {
            Err(ApiError::Unauthorized(_)) => {},
            Err(e) => panic!("Expected Unauthorized, got {:?}", e),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_create_account_validates_name() {
        let state = create_test_state();

        let request = CreateAccountRequest { name: "".to_string() };

        let admin_ctx = infera_types::AuthContext {
            tenant_id: "test".to_string(),
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_ADMIN.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: Uuid::nil(),
            account: Uuid::nil(),
        };

        let result = create_account(
            infera_auth::extractor::OptionalAuth(Some(admin_ctx)),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        match result {
            Err(ApiError::InvalidRequest(msg)) => {
                assert!(msg.contains("Account name cannot be empty"));
            },
            Err(e) => panic!("Expected InvalidRequest, got {:?}", e),
            Ok(_) => panic!("Expected error"),
        }
    }
}
