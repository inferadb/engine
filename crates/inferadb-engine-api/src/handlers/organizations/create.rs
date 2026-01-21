//! Create organization handler

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use inferadb_engine_types::{CreateOrganizationRequest, Organization, OrganizationResponse};

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::require_admin_scope,
    validation::validate_organization_name,
};

/// Create a new organization
///
/// This endpoint allows administrators to create new organizations.
/// Only users with the `inferadb.admin` scope can create organizations.
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
/// - 400 Bad Request: Invalid organization name
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn create_organization(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    axum::Json(request): axum::Json<CreateOrganizationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Require admin scope
    require_admin_scope(&auth.0)?;

    // Validate organization name
    validate_organization_name(&request.name)?;

    // Generate a unique ID using timestamp (nanoseconds since epoch)
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(1);

    // Create organization with generated ID
    let organization = Organization::new(id, request.name);

    // Store in database
    let created_organization = state
        .store
        .create_organization(organization)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(
        organization_id = %created_organization.id,
        organization_name = %created_organization.name,
        "Organization created"
    );

    // Convert to response and return 201 Created
    Ok((
        StatusCode::CREATED,
        ResponseData::new(OrganizationResponse::from(created_organization), format),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use inferadb_engine_config::Config;
    use inferadb_engine_const::scopes::SCOPE_ADMIN;
    use inferadb_engine_core::ipl::Schema;
    use inferadb_engine_repository::EngineStorage;
    use inferadb_engine_types::AuthMethod;
    use inferadb_storage::MemoryBackend;

    use super::*;
    use crate::{AppState, content_negotiation::ResponseFormat};

    fn create_test_state() -> AppState {
        let store: Arc<dyn inferadb_engine_store::InferaStore> =
            Arc::new(EngineStorage::new(MemoryBackend::new()));
        let schema = Arc::new(Schema::new(vec![]));
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::builder(store, schema, config).wasm_host(None).signing_key_cache(None).build()
    }

    #[tokio::test]
    async fn test_create_organization_requires_auth() {
        let state = create_test_state();

        let request = CreateOrganizationRequest { name: "Test Organization".to_string() };

        let result = create_organization(
            inferadb_engine_auth::extractor::OptionalAuth(None),
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
    async fn test_create_organization_validates_name() {
        let state = create_test_state();

        let request = CreateOrganizationRequest { name: "".to_string() };

        let admin_ctx = inferadb_engine_types::AuthContext {
            client_id: "test".to_string(),
            key_id: "test".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: vec![SCOPE_ADMIN.to_string()],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: 0i64,
            organization: 0i64,
        };

        let result = create_organization(
            inferadb_engine_auth::extractor::OptionalAuth(Some(admin_ctx)),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        match result {
            Err(ApiError::InvalidRequest(msg)) => {
                assert!(msg.contains("Organization name cannot be empty"));
            },
            Err(e) => panic!("Expected InvalidRequest, got {:?}", e),
            Ok(_) => panic!("Expected error"),
        }
    }
}
