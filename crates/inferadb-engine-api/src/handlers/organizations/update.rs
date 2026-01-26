//! Update organization handler

use axum::extract::{Path, State};
use inferadb_engine_types::{OrganizationResponse, UpdateOrganizationRequest};

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::require_admin_scope,
    validation::validate_organization_name,
};

/// Update an organization
///
/// This endpoint allows administrators to update organization details.
/// Only users with the `inferadb.admin` scope can update organizations.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.admin` scope
///
/// # Path Parameters
/// - `id`: Organization UUID
///
/// # Request Body
/// ```json
/// {
///   "name": "New Organization Name"
/// }
/// ```
///
/// # Response (200 OK)
/// ```json
/// {
///   "id": "550e8400-e29b-41d4-a716-446655440000",
///   "name": "New Organization Name",
///   "created_at": "2025-11-02T10:00:00Z",
///   "updated_at": "2025-11-02T11:00:00Z"
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing `inferadb.admin` scope
/// - 404 Not Found: Organization does not exist
/// - 400 Bad Request: Invalid organization name
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn update_organization(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(organization_id): Path<i64>,
    axum::Json(request): axum::Json<UpdateOrganizationRequest>,
) -> Result<ResponseData<OrganizationResponse>, ApiError> {
    // Require admin scope
    require_admin_scope(&auth.0)?;

    // Validate new name
    validate_organization_name(&request.name)?;

    // Get existing organization
    let mut organization = state
        .store
        .get_organization(organization_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Organization not found".to_string()))?;

    // Update fields
    organization.name = request.name;
    organization.updated_at = chrono::Utc::now();

    // Save to storage
    let updated_organization = state
        .store
        .update_organization(organization)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(
        organization_id = %updated_organization.id,
        new_name = %updated_organization.name,
        "Organization updated"
    );

    Ok(ResponseData::new(OrganizationResponse::from(updated_organization), format))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use inferadb_engine_config::Config;
    use inferadb_engine_const::scopes::SCOPE_ADMIN;
    use inferadb_engine_core::ipl::Schema;
    use inferadb_engine_repository::EngineStorage;
    use inferadb_engine_types::Organization;
    use inferadb_storage::MemoryBackend;

    use super::*;
    use crate::content_negotiation::ResponseFormat;

    fn create_test_state() -> AppState {
        let store: Arc<dyn inferadb_engine_store::InferaStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
        let schema = Arc::new(Schema::new(vec![]));
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::builder().store(store).schema(schema).config(config).build()
    }

    fn create_admin_context() -> inferadb_engine_types::AuthContext {
        inferadb_engine_types::AuthContext {
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: inferadb_engine_types::AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_ADMIN.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: 0i64,
            organization: 0i64,
        }
    }

    #[tokio::test]
    async fn test_update_organization_requires_admin() {
        let state = create_test_state();
        let organization_id = 999i64;
        let request = UpdateOrganizationRequest { name: "New Name".to_string() };

        let result = update_organization(
            inferadb_engine_auth::extractor::OptionalAuth(None),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(organization_id),
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Unauthorized(_) => {},
            e => panic!("Expected Unauthorized, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_update_organization_success() {
        let state = create_test_state();

        // Create test organization
        let organization = Organization::new(44444444444444i64, "Old Name".to_string());
        let created = state.store.create_organization(organization).await.unwrap();

        let request = UpdateOrganizationRequest { name: "New Name".to_string() };

        let result = update_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state.clone()),
            Path(created.id),
            axum::Json(request),
        )
        .await
        .unwrap();

        assert_eq!(result.data.name, "New Name");
        assert_eq!(result.data.id, created.id);

        // Verify it's actually updated in storage
        let stored = state.store.get_organization(created.id).await.unwrap().unwrap();
        assert_eq!(stored.name, "New Name");
    }

    #[tokio::test]
    async fn test_update_organization_not_found() {
        let state = create_test_state();
        let organization_id = 555i64;
        let request = UpdateOrganizationRequest { name: "New Name".to_string() };

        let result = update_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(organization_id),
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::UnknownTenant(_) => {},
            e => panic!("Expected UnknownTenant, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_update_organization_validates_name() {
        let state = create_test_state();

        // Create test organization
        let organization = Organization::new(55555555555555i64, "Old Name".to_string());
        let created = state.store.create_organization(organization).await.unwrap();

        let request = UpdateOrganizationRequest { name: "".to_string() };

        let result = update_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created.id),
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequest(msg) => {
                assert!(msg.contains("Organization name cannot be empty"));
            },
            e => panic!("Expected InvalidRequest, got {:?}", e),
        }
    }
}
