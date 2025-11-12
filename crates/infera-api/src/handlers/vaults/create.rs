//! Create vault handler

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use infera_types::{CreateVaultRequest, Vault, VaultResponse};
use uuid::Uuid;

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_account_access,
    validation::validate_vault_name,
};

/// Create a new vault for an account
///
/// This endpoint allows users to create vaults for accounts they own.
/// Authorization rules:
/// - Administrators (with `inferadb.admin` scope) can create vaults for any account
/// - Users can only create vaults for their own account
///
/// # Authorization
/// - Requires authentication
/// - Requires either `inferadb.admin` scope OR account ownership
///
/// # Path Parameters
/// - `account_id`: Account UUID that will own this vault
///
/// # Request Body
/// ```json
/// {
///   "name": "Production Vault"
/// }
/// ```
///
/// # Response (201 Created)
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
/// - 403 Forbidden: Not authorized to create vaults for this account
/// - 404 Not Found: Account does not exist
/// - 400 Bad Request: Invalid vault name
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn create_vault(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(account_id): Path<Uuid>,
    Json(request): Json<CreateVaultRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Check authorization (admin OR account owner)
    authorize_account_access(&auth.0, account_id)?;

    // Validate vault name
    validate_vault_name(&request.name)?;

    // Verify account exists
    state
        .store
        .get_account(account_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Account not found".to_string()))?;

    // Create vault with new UUID
    let vault = Vault::new(account_id, request.name);

    // Store in database
    let created_vault =
        state.store.create_vault(vault).await.map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(
        vault_id = %created_vault.id,
        vault_name = %created_vault.name,
        account_id = %created_vault.account,
        "Vault created"
    );

    // Convert to response and return 201 Created
    Ok((StatusCode::CREATED, ResponseData::new(VaultResponse::from(created_vault), format)))
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

    fn create_user_context(account_id: Uuid) -> infera_types::AuthContext {
        infera_types::AuthContext {
            tenant_id: "test".to_string(),
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: infera_types::AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_CHECK.to_string(), SCOPE_WRITE.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: Uuid::nil(),
            account: account_id,
        }
    }

    #[tokio::test]
    async fn test_create_vault_requires_auth() {
        let state = create_test_state();
        let account_id = Uuid::new_v4();
        let request = CreateVaultRequest { name: "Test Vault".to_string() };

        let result = create_vault(
            infera_auth::extractor::OptionalAuth(None),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(account_id),
            Json(request),
        )
        .await;

        match result {
            Err(ApiError::Unauthorized(_)) => {},
            Err(e) => panic!("Expected Unauthorized, got {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_create_vault_user_can_create_for_own_account() {
        let state = create_test_state();

        // Create account
        let account = Account::new("Test Account".to_string());
        let created_account = state.store.create_account(account).await.unwrap();

        let request = CreateVaultRequest { name: "My Vault".to_string() };

        let result = create_vault(
            infera_auth::extractor::OptionalAuth(Some(create_user_context(created_account.id))),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_account.id),
            Json(request),
        )
        .await
        .unwrap();

        let response = result.into_response();
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_create_vault_user_cannot_create_for_other_account() {
        let state = create_test_state();

        // Create account
        let account = Account::new("Other Account".to_string());
        let created_account = state.store.create_account(account).await.unwrap();

        // Try to create vault with different account ID in auth context
        let other_account_id = Uuid::new_v4();
        let request = CreateVaultRequest { name: "Vault".to_string() };

        let result = create_vault(
            infera_auth::extractor::OptionalAuth(Some(create_user_context(other_account_id))),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_account.id),
            Json(request),
        )
        .await;

        match result {
            Err(ApiError::Forbidden(_)) => {},
            Err(e) => panic!("Expected Forbidden, got {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_create_vault_admin_can_create_for_any_account() {
        let state = create_test_state();

        // Create account
        let account = Account::new("Any Account".to_string());
        let created_account = state.store.create_account(account).await.unwrap();

        let request = CreateVaultRequest { name: "Admin Vault".to_string() };

        let result = create_vault(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_account.id),
            Json(request),
        )
        .await
        .unwrap();

        let response = result.into_response();
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_create_vault_account_not_found() {
        let state = create_test_state();
        let account_id = Uuid::new_v4();
        let request = CreateVaultRequest { name: "Vault".to_string() };

        let result = create_vault(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(account_id),
            Json(request),
        )
        .await;

        match result {
            Err(ApiError::UnknownTenant(_)) => {},
            Err(e) => panic!("Expected UnknownTenant, got {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_create_vault_validates_name() {
        let state = create_test_state();

        // Create account
        let account = Account::new("Test Account".to_string());
        let created_account = state.store.create_account(account).await.unwrap();

        let request = CreateVaultRequest { name: "".to_string() };

        let result = create_vault(
            infera_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_account.id),
            Json(request),
        )
        .await;

        match result {
            Err(ApiError::InvalidRequest(msg)) => {
                assert!(msg.contains("Vault name cannot be empty"));
            },
            Err(e) => panic!("Expected InvalidRequest, got {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }
}
