//! Get organization handler

use axum::extract::{Path, State};
use inferadb_engine_types::OrganizationResponse;

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_organization_access,
};

/// Get an organization by ID
///
/// This endpoint allows users to retrieve organization details.
/// Authorization rules:
/// - Administrators (with `inferadb.admin` scope) can view any organization
/// - Users can only view their own organization
///
/// # Authorization
/// - Requires authentication
/// - Requires either `inferadb.admin` scope OR organization ownership
///
/// # Path Parameters
/// - `id`: Organization UUID
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
/// - 403 Forbidden: Not authorized to view this organization
/// - 404 Not Found: Organization does not exist
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn get_organization(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Path(organization_id): Path<i64>,
) -> Result<ResponseData<OrganizationResponse>, ApiError> {
    // Check authorization (admin OR organization owner)
    authorize_organization_access(&auth.0, organization_id)?;

    // Get organization from storage
    let organization = state
        .store
        .get_organization(organization_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::UnknownTenant("Organization not found".to_string()))?;

    tracing::debug!(organization_id = %organization.id, organization_name = %organization.name, "Organization retrieved");

    Ok(ResponseData::new(OrganizationResponse::from(organization), format))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_engine_config::Config;
    use inferadb_engine_const::scopes::{SCOPE_ADMIN, SCOPE_CHECK, SCOPE_WRITE};
    use inferadb_engine_core::ipl::Schema;
    use inferadb_engine_store::MemoryBackend;
    use inferadb_engine_types::Organization;

    use super::*;
    use crate::content_negotiation::ResponseFormat;

    fn create_test_state() -> AppState {
        let store: Arc<dyn inferadb_engine_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![]));
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::builder(store, schema, config)
            .wasm_host(None)
            .jwks_cache(None)
            .server_identity(None)
            .build()
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

    fn create_user_context(organization_id: i64) -> inferadb_engine_types::AuthContext {
        inferadb_engine_types::AuthContext {
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: inferadb_engine_types::AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_CHECK.to_string(), SCOPE_WRITE.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: 0i64,
            organization: organization_id,
        }
    }

    #[tokio::test]
    async fn test_get_organization_requires_auth() {
        let state = create_test_state();
        let organization_id = 999i64;

        let result = get_organization(
            inferadb_engine_auth::extractor::OptionalAuth(None),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(organization_id),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Unauthorized(_) => {},
            e => panic!("Expected Unauthorized, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_organization_admin_can_view_any() {
        let state = create_test_state();

        // Create test organization
        let organization = Organization::new(11111111111111i64, "Test Organization".to_string());
        let created = state.store.create_organization(organization).await.unwrap();

        let result = get_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created.id),
        )
        .await
        .unwrap();

        assert_eq!(result.data.id, created.id);
        assert_eq!(result.data.name, "Test Organization");
    }

    #[tokio::test]
    async fn test_get_organization_user_can_view_own() {
        let state = create_test_state();

        // Create test organization
        let organization = Organization::new(22222222222222i64, "My Organization".to_string());
        let created = state.store.create_organization(organization).await.unwrap();

        let result = get_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(create_user_context(created.id))),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(created.id),
        )
        .await
        .unwrap();

        assert_eq!(result.data.id, created.id);
    }

    #[tokio::test]
    async fn test_get_organization_user_cannot_view_other() {
        let state = create_test_state();

        // Create test organization
        let organization = Organization::new(33333333333333i64, "Other Organization".to_string());
        let created = state.store.create_organization(organization).await.unwrap();

        // Try to access with different organization ID
        let other_organization_id = 777i64;

        let result = get_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(create_user_context(
                other_organization_id,
            ))),
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
    async fn test_get_organization_not_found() {
        let state = create_test_state();
        let organization_id = 666i64;

        let result = get_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            Path(organization_id),
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::UnknownTenant(_) => {},
            e => panic!("Expected UnknownTenant, got {:?}", e),
        }
    }
}
