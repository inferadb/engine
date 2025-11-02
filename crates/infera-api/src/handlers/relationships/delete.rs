//! DELETE handler for exact relationship match
//!
//! Provides a REST-style DELETE endpoint to remove a specific relationship.
//! This is a convenience endpoint that wraps the native delete relationships functionality.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::ApiError;
use crate::AppState;
use infera_types::DeleteFilter;

use super::get::RelationshipPath;

/// Handler for `DELETE /v1/relationships/{resource}/{relation}/{subject}`
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
/// DELETE /v1/relationships/document:readme/view/user:alice
///
/// Response:
/// 204 No Content
/// X-Revision: "rev_abc123"
/// ```
#[tracing::instrument(skip(state), fields(exact_delete = true))]
pub async fn delete_relationship(
    State(state): State<AppState>,
    Path(params): Path<RelationshipPath>,
) -> Result<impl IntoResponse, ApiError> {
    let start = std::time::Instant::now();

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
        "Deleting exact relationship match"
    );

    // Validate parameters are non-empty
    if resource.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Resource cannot be empty".to_string(),
        ));
    }
    if relation.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Relation cannot be empty".to_string(),
        ));
    }
    if subject.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Subject cannot be empty".to_string(),
        ));
    }

    // Delete using exact match filters
    let delete_filter = DeleteFilter {
        resource: Some(resource.clone()),
        relation: Some(relation.clone()),
        subject: Some(subject.clone()),
    };

    let (revision, deleted_count) = state
        .store
        .delete_by_filter(&delete_filter, Some(1))
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to delete relationship: {}", e)))?;

    // Record metrics
    let duration = start.elapsed();
    infera_observe::metrics::record_api_request(
        "/v1/relationships/{resource}/{relation}/{subject}",
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
    use super::*;
    use crate::AppState;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::delete,
        Router,
    };
    use infera_config::Config;
    use infera_core::Evaluator;
    use infera_store::{MemoryBackend, RelationshipStore};
    use infera_types::Relationship;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn create_test_state() -> AppState {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());

        // Create a minimal schema
        use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "view".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        let evaluator = Arc::new(Evaluator::new(Arc::clone(&store), schema, None));
        let config = Arc::new(Config::default());
        let health_tracker = Arc::new(crate::health::HealthTracker::new());

        // Add test relationships
        store
            .write(vec![
                Relationship {
                    resource: "document:readme".to_string(),
                    relation: "view".to_string(),
                    subject: "user:alice".to_string(),
                },
                Relationship {
                    resource: "document:guide".to_string(),
                    relation: "view".to_string(),
                    subject: "user:bob".to_string(),
                },
            ])
            .await
            .unwrap();

        AppState {
            evaluator,
            store,
            config,
            jwks_cache: None,
            health_tracker,
        }
    }

    #[tokio::test]
    async fn test_delete_existing_relationship() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                delete(delete_relationship),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/relationships/document:readme/view/user:alice")
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
                "/v1/relationships/:resource/:relation/:subject",
                delete(delete_relationship),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/relationships/document:secret/view/user:charlie")
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
                "/v1/relationships/:resource/:relation/:subject",
                delete(delete_relationship),
            )
            .with_state(state.clone());

        let response1 = app1
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response1.status(), StatusCode::NO_CONTENT);

        // Second deletion of the same relationship
        let app2 = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                delete(delete_relationship),
            )
            .with_state(state);

        let response2 = app2
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/relationships/document:readme/view/user:alice")
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
            .write(vec![Relationship {
                resource: "document:file name".to_string(),
                relation: "view".to_string(),
                subject: "user:alice@example.com".to_string(),
            }])
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                delete(delete_relationship),
            )
            .with_state(state);

        // URL encode the parameters (space becomes %20, @ becomes %40, : becomes %3A)
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/relationships/document%3Afile%20name/view/user%3Aalice%40example.com")
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
            .write(vec![Relationship {
                resource: "document:file-name_with.dots".to_string(),
                relation: "view".to_string(),
                subject: "user:alice@example.com".to_string(),
            }])
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                delete(delete_relationship),
            )
            .with_state(state);

        // URL encode the special characters
        let encoded_resource = urlencoding::encode("document:file-name_with.dots");
        let encoded_subject = urlencoding::encode("user:alice@example.com");

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!(
                        "/v1/relationships/{}/view/{}",
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
                "/v1/relationships/:resource/:relation/:subject",
                delete(delete_relationship),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let revision = response
            .headers()
            .get("X-Revision")
            .unwrap()
            .to_str()
            .unwrap();

        // Revision should be a non-empty string
        assert!(!revision.is_empty());
    }
}
