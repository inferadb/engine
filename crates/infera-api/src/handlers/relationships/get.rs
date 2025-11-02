//! GET handler for exact relationship match
//!
//! Provides a REST-style GET endpoint to check if a specific relationship exists.
//! This is a convenience endpoint that wraps the native list relationships functionality.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ApiError;
use crate::AppState;
use infera_types::ListRelationshipsRequest;

/// Path parameters for exact relationship match
#[derive(Debug, Clone, Deserialize)]
pub struct RelationshipPath {
    /// Resource entity (e.g., "document:readme")
    pub resource: String,
    /// Relation name (e.g., "view")
    pub relation: String,
    /// Subject entity (e.g., "user:alice")
    pub subject: String,
}

/// Response for relationship existence check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipExistsResponse {
    /// Whether the relationship exists
    pub exists: bool,
    /// The relationship details if it exists
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<RelationshipDetails>,
}

/// Relationship details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipDetails {
    pub resource: String,
    pub relation: String,
    pub subject: String,
}

/// Handler for `GET /v1/relationships/{resource}/{relation}/{subject}`
///
/// This is a convenience endpoint that checks if a specific relationship exists.
/// It returns 200 OK if the relationship exists, or 404 Not Found if it doesn't.
///
/// # Path Parameters
///
/// - `resource`: Resource entity (URL-encoded, e.g., "document:readme")
/// - `relation`: Relation name (URL-encoded, e.g., "view")
/// - `subject`: Subject entity (URL-encoded, e.g., "user:alice")
///
/// # Response
///
/// - `200 OK`: Relationship exists, returns relationship details with ETag
/// - `404 Not Found`: Relationship does not exist
/// - `400 Bad Request`: Invalid parameters
///
/// # Caching
///
/// Responses include:
/// - `ETag`: Content hash for caching
/// - `Cache-Control`: max-age=60 (1 minute)
///
/// # Example
///
/// ```text
/// GET /v1/relationships/document:readme/view/user:alice
///
/// Response:
/// 200 OK
/// ETag: "abc123..."
/// Cache-Control: max-age=60
///
/// {
///   "exists": true,
///   "relationship": {
///     "resource": "document:readme",
///     "relation": "view",
///     "subject": "user:alice"
///   }
/// }
/// ```
#[tracing::instrument(skip(state), fields(exact_match = true))]
pub async fn get_relationship(
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
        "Checking exact relationship match"
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

    // Query the store using exact match filters
    let list_request = ListRelationshipsRequest {
        resource: Some(resource.clone()),
        relation: Some(relation.clone()),
        subject: Some(subject.clone()),
        limit: Some(1), // We only need to know if at least one exists
        cursor: None,
    };

    let response = state.evaluator.list_relationships(list_request).await?;

    // Record metrics
    let duration = start.elapsed();
    infera_observe::metrics::record_api_request(
        "/v1/relationships/{resource}/{relation}/{subject}",
        "GET",
        if response.relationships.is_empty() {
            404
        } else {
            200
        },
        duration.as_secs_f64(),
    );

    if response.relationships.is_empty() {
        tracing::info!(
            resource = %resource,
            relation = %relation,
            subject = %subject,
            duration_ms = duration.as_millis(),
            "Relationship not found"
        );

        // Return 404 with empty body
        return Ok((StatusCode::NOT_FOUND, [].into_iter().collect::<HeaderMap>()).into_response());
    }

    // Relationship exists - build response with ETag and caching headers
    let response_body = RelationshipExistsResponse {
        exists: true,
        relationship: Some(RelationshipDetails {
            resource: resource.clone(),
            relation: relation.clone(),
            subject: subject.clone(),
        }),
    };

    // Generate ETag based on relationship content
    let etag = generate_etag(&resource, &relation, &subject);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::ETAG,
        etag.parse()
            .map_err(|e| ApiError::Internal(format!("Failed to create ETag header: {}", e)))?,
    );
    headers.insert(
        header::CACHE_CONTROL,
        "max-age=60".parse().map_err(|e| {
            ApiError::Internal(format!("Failed to create Cache-Control header: {}", e))
        })?,
    );

    tracing::info!(
        resource = %resource,
        relation = %relation,
        subject = %subject,
        etag = %etag,
        duration_ms = duration.as_millis(),
        "Relationship found"
    );

    Ok((StatusCode::OK, headers, Json(response_body)).into_response())
}

/// Generate an ETag for a relationship
///
/// Uses SHA256 hash of the concatenated relationship components.
fn generate_etag(resource: &str, relation: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(resource.as_bytes());
    hasher.update(b"|");
    hasher.update(relation.as_bytes());
    hasher.update(b"|");
    hasher.update(subject.as_bytes());
    let result = hasher.finalize();
    format!("\"{}\"", hex::encode(&result[..8])) // Use first 8 bytes for brevity
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use infera_config::Config;
    use infera_core::Evaluator;
    use infera_store::{MemoryBackend, RelationshipStore};
    use infera_types::Relationship;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

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

        let evaluator = Arc::new(Evaluator::new(
            Arc::clone(&store),
            schema,
            None,
            uuid::Uuid::nil(),
        ));
        let config = Arc::new(Config::default());
        let health_tracker = Arc::new(crate::health::HealthTracker::new());

        // Add test relationships
        store
            .write(
                Uuid::nil(),
                vec![
                    Relationship {
                        vault: Uuid::nil(),
                        resource: "document:readme".to_string(),
                        relation: "view".to_string(),
                        subject: "user:alice".to_string(),
                    },
                    Relationship {
                        vault: Uuid::nil(),
                        resource: "document:guide".to_string(),
                        relation: "view".to_string(),
                        subject: "user:bob".to_string(),
                    },
                ],
            )
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
    async fn test_get_relationship_exists() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                get(get_relationship),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check headers
        assert!(response.headers().get(header::ETAG).is_some());
        assert!(response.headers().get(header::CACHE_CONTROL).is_some());

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: RelationshipExistsResponse = serde_json::from_slice(&body).unwrap();

        assert!(json.exists);
        assert!(json.relationship.is_some());

        let rel = json.relationship.unwrap();
        assert_eq!(rel.resource, "document:readme");
        assert_eq!(rel.relation, "view");
        assert_eq!(rel.subject, "user:alice");
    }

    #[tokio::test]
    async fn test_get_relationship_not_found() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                get(get_relationship),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/relationships/document:secret/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_relationship_url_encoded() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                get(get_relationship),
            )
            .with_state(state);

        // URL encode "document:readme" -> "document%3Areadme"
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/relationships/document%3Areadme/view/user%3Aalice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_relationship_special_characters() {
        let state = create_test_state().await;

        // Add a relationship with special characters
        state
            .store
            .write(
                Uuid::nil(),
                vec![Relationship {
                    vault: Uuid::nil(),
                    resource: "document:file-name_with.dots".to_string(),
                    relation: "view".to_string(),
                    subject: "user:alice@example.com".to_string(),
                }],
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                get(get_relationship),
            )
            .with_state(state);

        // URL encode the special characters
        let encoded_resource = urlencoding::encode("document:file-name_with.dots");
        let encoded_subject = urlencoding::encode("user:alice@example.com");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!(
                        "/v1/relationships/{}/view/{}",
                        encoded_resource, encoded_subject
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_etag_generation_deterministic() {
        let etag1 = generate_etag("document:readme", "view", "user:alice");
        let etag2 = generate_etag("document:readme", "view", "user:alice");

        assert_eq!(etag1, etag2, "ETags should be deterministic");
    }

    #[tokio::test]
    async fn test_etag_generation_unique() {
        let etag1 = generate_etag("document:readme", "view", "user:alice");
        let etag2 = generate_etag("document:guide", "view", "user:alice");

        assert_ne!(
            etag1, etag2,
            "Different relationships should have different ETags"
        );
    }

    #[tokio::test]
    async fn test_cache_control_header() {
        let state = create_test_state().await;

        let app = Router::new()
            .route(
                "/v1/relationships/:resource/:relation/:subject",
                get(get_relationship),
            )
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/relationships/document:readme/view/user:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cache_control = response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(cache_control, "max-age=60");
    }
}
