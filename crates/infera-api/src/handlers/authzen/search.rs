//! AuthZEN search endpoints
//!
//! Implements the AuthZEN-compliant search endpoints that provide a thin
//! adapter layer over InferaDB's native list resources and list subjects functionality.

use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::adapters::authzen::{parse_entity, AuthZENAction, AuthZENEntity, AuthZENSubject};
use crate::ApiError;
use crate::AppState;
use infera_types::ListResourcesRequest;

/// AuthZEN resource search request
///
/// Searches for resources that a subject can perform an action on.
///
/// # Example
/// ```json
/// {
///   "subject": {"type": "user", "id": "alice"},
///   "action": {"name": "view"},
///   "resource_type": "document",
///   "limit": 100,
///   "cursor": "optional-continuation-token"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENResourceSearchRequest {
    /// The subject performing the action
    pub subject: AuthZENSubject,

    /// The action being performed
    pub action: AuthZENAction,

    /// The type of resources to search for
    #[serde(rename = "type")]
    pub resource_type: String,

    /// Optional limit on number of resources to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Optional continuation token for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// AuthZEN resource search response
///
/// Returns a list of resources that match the search criteria.
///
/// # Example
/// ```json
/// {
///   "resources": [
///     {"type": "document", "id": "readme"},
///     {"type": "document", "id": "guide"}
///   ],
///   "cursor": "optional-continuation-token"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENResourceSearchResponse {
    /// List of resources matching the search criteria
    pub resources: Vec<AuthZENEntity>,

    /// Continuation token for pagination (if more results available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Handler for `POST /access/v1/search/resource`
///
/// This is a thin adapter that translates AuthZEN resource search requests to
/// InferaDB's native list_resources format, performs the search, and translates
/// the response back to AuthZEN format.
///
/// # AuthZEN Specification
///
/// Request format:
/// ```json
/// {
///   "subject": {"type": "user", "id": "alice"},
///   "action": {"name": "view"},
///   "type": "document",
///   "limit": 100
/// }
/// ```
///
/// Response format:
/// ```json
/// {
///   "resources": [
///     {"type": "document", "id": "readme"},
///     {"type": "document", "id": "guide"}
///   ]
/// }
/// ```
#[tracing::instrument(skip(state), fields(authzen_alias = true, search_type = "resource"))]
pub async fn post_search_resource(
    State(state): State<AppState>,
    Json(request): Json<AuthZENResourceSearchRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let start = std::time::Instant::now();

    // Validate required fields
    if request.subject.subject_type.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Subject type cannot be empty".to_string(),
        ));
    }
    if request.subject.id.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Subject id cannot be empty".to_string(),
        ));
    }
    if request.action.name.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Action name cannot be empty".to_string(),
        ));
    }
    if request.resource_type.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Resource type cannot be empty".to_string(),
        ));
    }

    // Convert AuthZEN request to native format
    let subject = format!("{}:{}", request.subject.subject_type, request.subject.id);
    let permission = request.action.name.clone();
    let resource_type = request.resource_type.clone();

    // Validate the generated subject string
    parse_entity(&subject)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid subject format: {}", e)))?;

    tracing::debug!(
        subject = %subject,
        permission = %permission,
        resource_type = %resource_type,
        limit = ?request.limit,
        "Converted AuthZEN resource search request to native format"
    );

    // Convert to core request
    let list_request = ListResourcesRequest {
        subject,
        resource_type: resource_type.clone(),
        permission,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
        resource_id_pattern: None,
    };

    // Execute the search operation
    let response = state.evaluator.list_resources(list_request).await?;

    // Convert native response to AuthZEN format
    let authzen_resources: Result<Vec<AuthZENEntity>, ApiError> = response
        .resources
        .iter()
        .map(|resource_str| {
            parse_entity(resource_str)
                .map_err(|e| ApiError::Internal(format!("Failed to parse resource: {}", e)))
        })
        .collect();

    let authzen_resources = authzen_resources?;

    // Record API request metric
    let duration = start.elapsed();
    infera_observe::metrics::record_api_request(
        "/access/v1/search/resource",
        "POST",
        200,
        duration.as_secs_f64(),
    );

    tracing::info!(
        resource_count = response.resources.len(),
        has_cursor = response.cursor.is_some(),
        duration_ms = duration.as_millis(),
        "AuthZEN resource search completed"
    );

    Ok(Json(AuthZENResourceSearchResponse {
        resources: authzen_resources,
        cursor: response.cursor,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
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

        // Create a schema with document type and view relation
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
                    subject: "user:alice".to_string(),
                },
                Relationship {
                    resource: "document:secret".to_string(),
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
    async fn test_search_resource_basic() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: AuthZENResourceSearchResponse = serde_json::from_slice(&body).unwrap();

        // Alice should have access to readme and guide
        assert_eq!(json.resources.len(), 2);

        let resource_ids: Vec<String> = json.resources.iter().map(|r| r.id.clone()).collect();
        assert!(resource_ids.contains(&"readme".to_string()));
        assert!(resource_ids.contains(&"guide".to_string()));

        // Verify all resources have correct type
        for resource in &json.resources {
            assert_eq!(resource.entity_type, "document");
        }
    }

    #[tokio::test]
    async fn test_search_resource_no_matches() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "charlie".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: AuthZENResourceSearchResponse = serde_json::from_slice(&body).unwrap();

        // Charlie has no access to any documents
        assert_eq!(json.resources.len(), 0);
        assert!(json.cursor.is_none());
    }

    #[tokio::test]
    async fn test_search_resource_with_limit() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: Some(1),
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: AuthZENResourceSearchResponse = serde_json::from_slice(&body).unwrap();

        // Should only return 1 resource due to limit
        assert_eq!(json.resources.len(), 1);
    }

    #[tokio::test]
    async fn test_search_resource_empty_subject_type() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_resource_empty_subject_id() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_resource_empty_action() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_resource_empty_resource_type() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "".to_string(),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_resource_invalid_subject_format() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "User".to_string(), // Invalid: uppercase
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/resource")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
