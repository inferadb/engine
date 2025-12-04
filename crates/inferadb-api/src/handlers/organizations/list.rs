//! List organizations handler

use axum::extract::{Query, State};
use inferadb_types::{ListOrganizationsResponse, OrganizationResponse};
use serde::Deserialize;

use crate::{
    ApiError, AppState,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::require_admin_scope,
};

/// Query parameters for listing organizations
#[derive(Debug, Deserialize)]
pub struct ListQueryParams {
    /// Optional limit on number of organizations to return
    pub limit: Option<usize>,
}

/// List all organizations
///
/// This endpoint allows administrators to list all organizations in the system.
/// Only users with the `inferadb.admin` scope can list organizations.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.admin` scope
///
/// # Query Parameters
/// - `limit` (optional): Maximum number of organizations to return
///
/// # Response (200 OK)
/// ```json
/// {
///   "organizations": [
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
pub async fn list_organizations(
    auth: inferadb_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Query(params): Query<ListQueryParams>,
) -> Result<ResponseData<ListOrganizationsResponse>, ApiError> {
    // Require admin scope
    require_admin_scope(&auth.0)?;

    // List organizations from storage
    let organizations = state
        .store
        .list_organizations(params.limit)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::debug!(count = organizations.len(), "Listed organizations");

    // Convert to response
    let response = ListOrganizationsResponse {
        organizations: organizations.into_iter().map(OrganizationResponse::from).collect(),
    };

    Ok(ResponseData::new(response, format))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_config::Config;
    use inferadb_const::scopes::SCOPE_ADMIN;
    use inferadb_core::ipl::Schema;
    use inferadb_store::MemoryBackend;
    use inferadb_types::Organization;

    use super::*;
    use crate::content_negotiation::ResponseFormat;

    fn create_test_state() -> AppState {
        let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![]));
        let test_vault = 1i64;
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::builder(store, schema, config)
            .wasm_host(None)
            .jwks_cache(None)
            .default_vault(test_vault)
            .default_organization(0i64)
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

    #[tokio::test]
    async fn test_list_organizations_requires_admin() {
        let state = create_test_state();
        let params = Query(ListQueryParams { limit: None });

        let result = list_organizations(
            inferadb_auth::extractor::OptionalAuth(None),
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
    async fn test_list_organizations_success() {
        let state = create_test_state();

        // Create test organizations
        let organization1 = Organization::new(66666666666666i64, "Organization 1".to_string());
        let organization2 = Organization::new(77777777777777i64, "Organization 2".to_string());
        state.store.create_organization(organization1).await.unwrap();
        state.store.create_organization(organization2).await.unwrap();

        let params = Query(ListQueryParams { limit: None });

        let result = list_organizations(
            inferadb_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            params,
        )
        .await
        .unwrap();

        assert_eq!(result.data.organizations.len(), 2);
    }

    #[tokio::test]
    async fn test_list_organizations_with_limit() {
        let state = create_test_state();

        // Create test organizations
        for i in 0..5 {
            let organization = Organization::new(i as i64, format!("Organization {}", i));
            state.store.create_organization(organization).await.unwrap();
        }

        let params = Query(ListQueryParams { limit: Some(3) });

        let result = list_organizations(
            inferadb_auth::extractor::OptionalAuth(Some(create_admin_context())),
            AcceptHeader(ResponseFormat::Json),
            State(state),
            params,
        )
        .await
        .unwrap();

        assert_eq!(result.data.organizations.len(), 3);
    }
}
