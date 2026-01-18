//! Delete relationships handlers
//!
//! This module contains handlers for deleting relationships via two API styles:
//! - REST DELETE: `DELETE /access/v1/relationships/{resource}/{relation}/{subject}` - Single exact
//!   match
//! - JSON POST: `POST /access/v1/relationships/delete` - Bulk deletion with filters/lists
//!
//! Both handlers share the same core deletion logic to ensure consistent behavior,
//! validation, and cache invalidation.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use inferadb_engine_const::scopes::SCOPE_WRITE;
use inferadb_engine_types::{DeleteFilter, Relationship, RelationshipKey, Revision};
use serde::{Deserialize, Serialize};

use super::get::RelationshipPath;
use crate::{
    ApiError, AppState, Result,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_request,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteRequest {
    /// Optional filter for bulk deletion
    /// If provided, all relationships matching the filter will be deleted
    pub filter: Option<DeleteFilter>,
    /// Optional exact relationships to delete
    /// Can be combined with filter
    pub relationships: Option<Vec<Relationship>>,
    /// Maximum number of relationships to delete (safety limit)
    /// If not specified, uses default limit (1000) for filter-based deletes
    /// Set to 0 for unlimited (use with extreme caution!)
    pub limit: Option<usize>,
    /// Optional expected revision for optimistic locking
    /// If provided, the delete will only succeed if the current store revision matches
    pub expected_revision: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteResponse {
    pub revision: String,
    pub relationships_deleted: usize,
}

/// Core deletion logic used by both REST DELETE and POST endpoints
///
/// This function handles the actual deletion and cache invalidation,
/// ensuring consistent behavior across different API styles.
/// Returns (revision, count, deleted_relationships) where deleted_relationships
/// contains the exact relationships that were deleted (for change feed publishing).
async fn delete_relationships_internal(
    vault: i64,
    state: &AppState,
    request: DeleteRequest,
) -> Result<(Revision, usize, Vec<Relationship>)> {
    // Validate that at least one deletion method is specified
    let has_filter = request.filter.is_some();
    let has_relationships = request.relationships.as_ref().is_some_and(|r| !r.is_empty());

    if !has_filter && !has_relationships {
        return Err(ApiError::InvalidRequest(
            "Must provide either filter or relationships to delete".to_string(),
        ));
    }

    // Optimistic locking: Check expected revision if provided
    if let Some(expected_rev) = &request.expected_revision {
        let current_rev = state
            .store
            .get_revision(vault)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to get revision: {}", e)))?;

        let current_rev_str = current_rev.0.to_string();
        if &current_rev_str != expected_rev {
            return Err(ApiError::RevisionMismatch {
                expected: expected_rev.clone(),
                actual: current_rev_str,
            });
        }
    }

    let mut total_deleted = 0;
    let mut last_revision = None;
    let mut affected_resources = std::collections::HashSet::new();
    let mut deleted_relationships = Vec::new();

    // Handle filter-based deletion if filter is provided
    if let Some(filter) = request.filter {
        // Validate filter is not empty
        if filter.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Filter must have at least one field set to avoid deleting all relationships"
                    .to_string(),
            ));
        }

        // Apply default limit of 1000 if not specified, 0 means unlimited
        let limit = match request.limit {
            Some(0) => None,    // 0 means unlimited
            Some(n) => Some(n), // Explicit limit
            None => Some(1000), // Default limit
        };

        // Track affected resources for cache invalidation
        if let Some(ref resource) = filter.resource {
            affected_resources.insert(resource.clone());
        }

        // Perform batch deletion
        let (revision, count) = state
            .store
            .delete_by_filter(vault, &filter, limit)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to delete by filter: {}", e)))?;

        last_revision = Some(revision);
        total_deleted += count;
    }

    // Handle exact relationship deletion if relationships are provided
    if let Some(relationships) = request.relationships {
        if !relationships.is_empty() {
            // Validate and convert relationships to RelationshipKeys
            let mut keys = Vec::new();
            for relationship in &relationships {
                if relationship.resource.is_empty() {
                    return Err(ApiError::InvalidRequest(
                        "Relationship resource cannot be empty".to_string(),
                    ));
                }
                if relationship.relation.is_empty() {
                    return Err(ApiError::InvalidRequest(
                        "Relationship relation cannot be empty".to_string(),
                    ));
                }
                if relationship.subject.is_empty() {
                    return Err(ApiError::InvalidRequest(
                        "Relationship subject cannot be empty".to_string(),
                    ));
                }
                // Validate format (should contain colon)
                if !relationship.resource.contains(':') {
                    return Err(ApiError::InvalidRequest(format!(
                        "Invalid object format '{}': must be 'type:id'",
                        relationship.resource
                    )));
                }
                if !relationship.subject.contains(':') {
                    return Err(ApiError::InvalidRequest(format!(
                        "Invalid user format '{}': must be 'type:id'",
                        relationship.subject
                    )));
                }

                // Track resource for cache invalidation
                affected_resources.insert(relationship.resource.clone());

                keys.push(RelationshipKey {
                    resource: relationship.resource.clone(),
                    relation: relationship.relation.clone(),
                    subject: Some(relationship.subject.clone()),
                });
            }

            // Delete relationships from store
            for (key, relationship) in keys.into_iter().zip(relationships.into_iter()) {
                match state.store.delete(vault, &key).await {
                    Ok(revision) => {
                        last_revision = Some(revision);
                        total_deleted += 1;
                        // Track deleted relationship for change feed
                        deleted_relationships.push(Relationship {
                            vault,
                            resource: relationship.resource,
                            relation: relationship.relation,
                            subject: relationship.subject,
                        });
                    },
                    Err(e) => {
                        tracing::warn!("Failed to delete relationship {:?}: {}", key, e);
                        // Continue deleting other relationships even if one fails
                    },
                }
            }
        }
    }

    // Return the last revision from successful deletes
    let revision = last_revision
        .ok_or_else(|| ApiError::Internal("No relationships were deleted".to_string()))?;

    // Invalidate cache for affected resources
    let resources_vec: Vec<String> = affected_resources.into_iter().collect();
    state.relationship_service.invalidate_cache_for_resources(&resources_vec).await;

    Ok((revision, total_deleted, deleted_relationships))
}

/// Delete relationships endpoint (POST /access/v1/relationships/delete)
///
/// This endpoint supports bulk deletion operations via JSON POST body.
/// It supports both filter-based deletion and exact relationship lists.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.write` scope
///
/// # Request Body
/// ```json
/// {
///   "filter": {
///     "resource": "document:readme",
///     "relation": "view",
///     "subject": "user:alice"
///   },
///   "relationships": [
///     {
///       "resource": "document:readme",
///       "relation": "view",
///       "subject": "user:alice"
///     }
///   ],
///   "limit": 1000,
///   "expected_revision": "123"
/// }
/// ```
///
/// # Response (200 OK)
/// ```json
/// {
///   "revision": "124",
///   "relationships_deleted": 5
/// }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing required scope
/// - 400 Bad Request: Invalid request format
/// - 409 Conflict: Revision mismatch (optimistic locking)
/// - 500 Internal Server Error: Storage operation failed
#[tracing::instrument(skip(state))]
pub async fn delete_relationships_handler(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Json(request): Json<DeleteRequest>,
) -> Result<ResponseData<DeleteResponse>> {
    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, &[SCOPE_WRITE])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            vault = %vault,
            tenant_id = %auth_ctx.organization,
            "Delete request from tenant"
        );
    }

    // Call internal deletion function
    let (revision, total_deleted, _deleted_relationships) =
        delete_relationships_internal(vault, &state, request).await?;

    Ok(ResponseData::new(
        DeleteResponse { revision: revision.0.to_string(), relationships_deleted: total_deleted },
        format,
    ))
}

/// Handler for `DELETE /access/v1/relationships/{resource}/{relation}/{subject}`
///
/// This is a convenience endpoint that deletes a specific relationship.
/// It always returns 204 No Content, regardless of whether the relationship existed.
/// This makes the operation idempotent - deleting the same relationship multiple times
/// has the same effect as deleting it once.
///
/// # Path Parameters
///
/// - `resource`: Resource entity (URL-encoded, e.g., "document:readme")
/// - `relation`: Relation name (URL-encoded, e.g., "view")
/// - `subject`: Subject entity (URL-encoded, e.g., "user:alice")
///
/// # Response
///
/// - `204 No Content`: Relationship deleted (or didn't exist)
/// - `400 Bad Request`: Invalid parameters
///
/// # Headers
///
/// Response includes:
/// - `X-Revision`: Revision token after deletion
///
/// # Idempotency
///
/// This endpoint is idempotent. Deleting a relationship that doesn't exist
/// returns the same 204 No Content response as deleting one that does exist.
///
/// # Example
///
/// ```text
/// DELETE /access/v1/relationships/document:readme/view/user:alice
///
/// Response:
/// 204 No Content
/// X-Revision: "rev_abc123"
/// ```
#[tracing::instrument(skip(state, auth), fields(exact_delete = true))]
pub async fn delete_relationship(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Path(params): Path<RelationshipPath>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let start = std::time::Instant::now();

    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, &[SCOPE_WRITE])?;

    // URL-decode path parameters (they come URL-encoded from the router)
    let resource = urlencoding::decode(&params.resource)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid resource encoding: {}", e)))?
        .into_owned();

    let relation = urlencoding::decode(&params.relation)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid relation encoding: {}", e)))?
        .into_owned();

    let subject = urlencoding::decode(&params.subject)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid subject encoding: {}", e)))?
        .into_owned();

    tracing::debug!(
        resource = %resource,
        relation = %relation,
        subject = %subject,
        vault = %vault,
        "Deleting exact relationship match"
    );

    // Create a DeleteRequest with the exact relationship to delete
    let delete_request = DeleteRequest {
        filter: None,
        relationships: Some(vec![Relationship {
            vault,
            resource: resource.clone(),
            relation: relation.clone(),
            subject: subject.clone(),
        }]),
        limit: None,
        expected_revision: None,
    };

    // Call internal deletion logic (validates, deletes, and invalidates cache)
    let (revision, deleted_count, _deleted_relationships) =
        delete_relationships_internal(vault, &state, delete_request).await?;

    // Record metrics
    let duration = start.elapsed();
    inferadb_engine_observe::metrics::record_api_request(
        "/access/v1/relationships/{resource}/{relation}/{subject}",
        "DELETE",
        204,
        duration.as_secs_f64(),
    );

    tracing::info!(
        resource = %resource,
        relation = %relation,
        subject = %subject,
        deleted_count = deleted_count,
        revision = %revision.0,
        duration_ms = duration.as_millis(),
        "Relationship deletion completed"
    );

    // Build response headers with revision token
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Revision",
        revision.0.to_string().parse().map_err(|e| {
            ApiError::Internal(format!("Failed to create X-Revision header: {}", e))
        })?,
    );

    // Always return 204 No Content for idempotency
    // Whether the relationship existed or not, the end state is the same
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::delete,
    };
    use inferadb_engine_config::Config;
    use inferadb_engine_repository::EngineStorage;
    use inferadb_engine_types::Relationship;
    use inferadb_storage::MemoryBackend;
    use tower::ServiceExt;

    use super::*;
    use crate::{AppState, test_utils::with_test_auth};

    async fn create_test_state() -> AppState {
        let store: Arc<dyn inferadb_engine_store::InferaStore> =
            Arc::new(EngineStorage::new(MemoryBackend::new()));

        // Create a minimal schema
        use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "view".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        // Use a test vault ID
        let test_vault = 1i64;
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        // Add test relationships
        store
            .write(
                test_vault,
                vec![
                    Relationship {
                        vault: test_vault,
                        resource: "document:readme".to_string(),
                        relation: "view".to_string(),
                        subject: "user:alice".to_string(),
                    },
                    Relationship {
                        vault: test_vault,
                        resource: "document:guide".to_string(),
                        relation: "view".to_string(),
                        subject: "user:bob".to_string(),
                    },
                ],
            )
            .await
            .unwrap();

        AppState::builder(store, schema, config)
            .wasm_host(None)
            .jwks_cache(None)
            .server_identity(None)
            .build()
    }

    /// Test vault ID that matches what with_test_auth uses
    const TEST_VAULT: i64 = 1;

    #[tokio::test]
    async fn test_delete_existing_relationship() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/access/v1/relationships/{resource}/{relation}/{subject}",
                delete(delete_relationship),
            )
            .with_state(state.clone());
        let app = with_test_auth(app);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/access/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Check X-Revision header is present
        assert!(response.headers().get("X-Revision").is_some());
    }

    #[tokio::test]
    async fn test_delete_non_existent_relationship() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/access/v1/relationships/{resource}/{relation}/{subject}",
                delete(delete_relationship),
            )
            .with_state(state.clone());
        let app = with_test_auth(app);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/access/v1/relationships/document:secret/view/user:charlie")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 204 even if relationship didn't exist (idempotent)
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // X-Revision header should still be present
        assert!(response.headers().get("X-Revision").is_some());
    }

    #[tokio::test]
    async fn test_delete_idempotency() {
        let state = create_test_state().await;

        // First deletion
        let app1 = Router::new()
            .route(
                "/access/v1/relationships/{resource}/{relation}/{subject}",
                delete(delete_relationship),
            )
            .with_state(state.clone());
        let app1 = with_test_auth(app1);

        let response1 = app1
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/access/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response1.status(), StatusCode::NO_CONTENT);

        // Second deletion of the same relationship
        let app2 = Router::new()
            .route(
                "/access/v1/relationships/{resource}/{relation}/{subject}",
                delete(delete_relationship),
            )
            .with_state(state.clone());
        let app2 = with_test_auth(app2);

        let response2 = app2
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/access/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should also return 204 (idempotent)
        assert_eq!(response2.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_with_url_encoded_parameters() {
        let state = create_test_state().await;

        // Add a relationship with URL-encodable characters
        state
            .store
            .write(
                TEST_VAULT,
                vec![Relationship {
                    vault: TEST_VAULT,
                    resource: "document:file name".to_string(),
                    relation: "view".to_string(),
                    subject: "user:alice@example.com".to_string(),
                }],
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/access/v1/relationships/{resource}/{relation}/{subject}",
                delete(delete_relationship),
            )
            .with_state(state.clone());
        let app = with_test_auth(app);

        // URL encode the parameters (space becomes %20, @ becomes %40, : becomes %3A)
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/access/v1/relationships/document%3Afile%20name/view/user%3Aalice%40example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_with_special_characters() {
        let state = create_test_state().await;

        // Add a relationship with special characters
        state
            .store
            .write(
                TEST_VAULT,
                vec![Relationship {
                    vault: TEST_VAULT,
                    resource: "document:file-name_with.dots".to_string(),
                    relation: "view".to_string(),
                    subject: "user:alice@example.com".to_string(),
                }],
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/access/v1/relationships/{resource}/{relation}/{subject}",
                delete(delete_relationship),
            )
            .with_state(state.clone());
        let app = with_test_auth(app);

        // URL encode the special characters
        let encoded_resource = urlencoding::encode("document:file-name_with.dots");
        let encoded_subject = urlencoding::encode("user:alice@example.com");

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/access/v1/relationships/{}/view/{}",
                        encoded_resource, encoded_subject
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_revision_header_format() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/access/v1/relationships/{resource}/{relation}/{subject}",
                delete(delete_relationship),
            )
            .with_state(state.clone());
        let app = with_test_auth(app);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/access/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let revision = response.headers().get("X-Revision").unwrap().to_str().unwrap();

        // Revision should be a non-empty string
        assert!(!revision.is_empty());
    }
}
