//! Create vault handler

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use inferadb_types::{CreateVaultRequest, Vault, VaultResponse};

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_organization_access,
    validation::validate_vault_name,
};

/// Create a new vault for an organization
///
/// This endpoint allows users to create vaults for organizations they own.
/// Authorization rules:
/// - Administrators (with `inferadb.admin` scope) can create vaults for any organization
/// - Users can only create vaults for their own organization
///
/// # Authorization
/// - Requires authentication
/// - Requires either `inferadb.admin` scope OR organization ownership
///
/// # Path Parameters
/// - `organization_id`: Organization UUID that will own this vault
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
///   "organization": "550e8400-e29b-41d4-a716-446655440000",
///   "name": "Production Vault",
///   "created_at": "2025-11-02T10:00:00Z",
///   "updated_at": "2025-11-02T10:00:00Z"
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Not authorized to create vaults for this organization
/// - 404 Not Found: Organization does not exist
/// - 400 Bad Request: Invalid vault name
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn create_vault(
    auth: inferadb_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(organization_id): Path<i64>,
    Json(request): Json<CreateVaultRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Check authorization (admin OR organization owner)
    authorize_organization_access(&auth.0, organization_id)?;

    // Validate vault name
    validate_vault_name(&request.name)?;

    // Verify organization exists
    state
        .store
        .get_organization(organization_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Organization not found".to_string()))?;

    // Generate a unique ID using timestamp (nanoseconds since epoch)
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(1);

    // Create vault with generated ID
    let vault = Vault::new(id, organization_id, request.name);

    // Store in database
    let created_vault =
        state.store.create_vault(vault).await.map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(
        vault_id = %created_vault.id,
        vault_name = %created_vault.name,
        organization_id = %created_vault.organization,
        "Vault created"
    );

    // Convert to response and return 201 Created
    Ok((StatusCode::CREATED, ResponseData::new(VaultResponse::from(created_vault), format)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_config::Config;
    use inferadb_const::scopes::{SCOPE_ADMIN, SCOPE_CHECK, SCOPE_WRITE};
    use inferadb_core::ipl::Schema;
    use inferadb_store::MemoryBackend;
    use inferadb_types::Organization;

    use super::*;
    use crate::content_negotiation::ResponseFormat;

    fn create_test_state() -> AppState {
        let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![]));
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::builder(store, schema, config)
            .wasm_host(None)
            .jwks_cache(None)
            .server_identity(None)
            .build()
    }

    fn create_admin_context() -> inferadb_types::AuthContext {
        inferadb_types::AuthContext {
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: inferadb_types::AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_ADMIN.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: 0i64,
            organization: 0i64,
        }
    }

    fn create_user_context(organization_id: i64) -> inferadb_types::AuthContext {
        inferadb_types::AuthContext {
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: inferadb_types::AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_CHECK.to_string(), SCOPE_WRITE.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: 0i64,
            organization: organization_id,
        }
    }

    #[tokio::test]
    async fn test_create_vault_requires_auth() {
        let state = create_test_state();
        let organization_id = 999i64;
        let request = CreateVaultRequest { name: "Test Vault".to_string() };

        let result = create_vault(
            inferadb_auth::extractor::OptionalAuth(None),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(organization_id),
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
    async fn test_create_vault_user_can_create_for_own_organization() {
        let state = create_test_state();

        // Create organization
        let organization = Organization::new(88888888888888i64, "Test Organization".to_string());
        let created_organization = state.store.create_organization(organization).await.unwrap();

        let request = CreateVaultRequest { name: "My Vault".to_string() };

        let result = create_vault(
            inferadb_auth::extractor::OptionalAuth(Some(create_user_context(
                created_organization.id,
            ))),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_organization.id),
            Json(request),
        )
        .await
        .unwrap();

        let response = result.into_response();
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_create_vault_user_cannot_create_for_other_organization() {
        let state = create_test_state();

        // Create organization
        let organization = Organization::new(99999999999999i64, "Other Organization".to_string());
        let created_organization = state.store.create_organization(organization).await.unwrap();

        // Try to create vault with different organization ID in auth context
        let other_organization_id = 888i64;
        let request = CreateVaultRequest { name: "Vault".to_string() };

        let result = create_vault(
            inferadb_auth::extractor::OptionalAuth(Some(create_user_context(
                other_organization_id,
            ))),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_organization.id),
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
    async fn test_create_vault_admin_can_create_for_any_organization() {
        let state = create_test_state();

        // Create organization
        let organization = Organization::new(10101010101010i64, "Any Organization".to_string());
        let created_organization = state.store.create_organization(organization).await.unwrap();

        let request = CreateVaultRequest { name: "Admin Vault".to_string() };

        let result = create_vault(
            inferadb_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_organization.id),
            Json(request),
        )
        .await
        .unwrap();

        let response = result.into_response();
        let (parts, _body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_create_vault_organization_not_found() {
        let state = create_test_state();
        let organization_id = 777i64;
        let request = CreateVaultRequest { name: "Vault".to_string() };

        let result = create_vault(
            inferadb_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(organization_id),
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

        // Create organization
        let organization = Organization::new(12121212121212i64, "Test Organization".to_string());
        let created_organization = state.store.create_organization(organization).await.unwrap();

        let request = CreateVaultRequest { name: "".to_string() };

        let result = create_vault(
            inferadb_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created_organization.id),
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
