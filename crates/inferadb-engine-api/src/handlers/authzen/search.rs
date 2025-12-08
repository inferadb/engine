//! AuthZEN search endpoints
//!
//! Implements the AuthZEN-compliant search endpoints that provide a thin
//! adapter layer over InferaDB's native list resources and list subjects functionality.

use axum::extract::State;
use inferadb_engine_const::scopes::*;
use inferadb_engine_types::{ListResourcesRequest, ListSubjectsRequest};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState,
    adapters::authzen::{
        AuthZENAction, AuthZENEntity, AuthZENResource, AuthZENSubject, parse_entity,
    },
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::{auth::authorize_request, validation::safe_format_entity},
    validation::{
        validate_authzen_resource_search_request, validate_authzen_subject_search_request,
    },
};

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
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.list` scope
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
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    request: axum::Json<AuthZENResourceSearchRequest>,
) -> Result<ResponseData<AuthZENResourceSearchResponse>, ApiError> {
    let start = std::time::Instant::now();

    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, &[SCOPE_LIST])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            tenant_id = auth_ctx.organization,
            vault = %vault,
            "AuthZEN resource search request with authentication"
        );
    }

    // Validate required fields
    validate_authzen_resource_search_request(&request.0)?;

    // Convert AuthZEN request to native format with injection protection
    let subject = safe_format_entity(&request.0.subject.subject_type, &request.0.subject.id)?;
    let permission = request.0.action.name.clone();
    let resource_type = request.0.resource_type.clone();

    // Validate the generated subject string
    parse_entity(&subject)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid subject format: {}", e)))?;

    tracing::debug!(
        subject = %subject,
        permission = %permission,
        resource_type = %resource_type,
        limit = ?request.0.limit,
        "Converted AuthZEN resource search request to native format"
    );

    // Convert to core request
    let list_request = ListResourcesRequest {
        subject,
        resource_type: resource_type.clone(),
        permission,
        limit: request.0.limit.map(|l| l as usize),
        cursor: request.0.cursor,
        resource_id_pattern: None,
    };

    // Execute the search operation using resource service
    let response = state.resource_service.list_resources(vault, list_request).await?;

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
    inferadb_engine_observe::metrics::record_api_request(
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

    Ok(ResponseData::new(
        AuthZENResourceSearchResponse { resources: authzen_resources, cursor: response.cursor },
        format,
    ))
}

/// AuthZEN subject search request
///
/// Searches for subjects that have a specific relation to a resource.
///
/// # Example
/// ```json
/// {
///   "resource": {"type": "document", "id": "readme"},
///   "action": {"name": "view"},
///   "subject_type": "user",
///   "limit": 100,
///   "cursor": "optional-continuation-token"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENSubjectSearchRequest {
    /// The resource being accessed
    pub resource: AuthZENResource,

    /// The action being performed
    pub action: AuthZENAction,

    /// Optional filter by subject type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// Optional limit on number of subjects to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Optional continuation token for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// AuthZEN subject search response
///
/// Returns a list of subjects that match the search criteria.
///
/// # Example
/// ```json
/// {
///   "subjects": [
///     {"type": "user", "id": "alice"},
///     {"type": "user", "id": "bob"}
///   ],
///   "cursor": "optional-continuation-token"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENSubjectSearchResponse {
    /// List of subjects matching the search criteria
    pub subjects: Vec<AuthZENEntity>,

    /// Continuation token for pagination (if more results available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Handler for `POST /access/v1/search/subject`
///
/// This is a thin adapter that translates AuthZEN subject search requests to
/// InferaDB's native list_subjects format, performs the search, and translates
/// the response back to AuthZEN format.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.list` scope
///
/// # AuthZEN Specification
///
/// Request format:
/// ```json
/// {
///   "resource": {"type": "document", "id": "readme"},
///   "action": {"name": "view"},
///   "subject_type": "user",
///   "limit": 100
/// }
/// ```
///
/// Response format:
/// ```json
/// {
///   "subjects": [
///     {"type": "user", "id": "alice"},
///     {"type": "user", "id": "bob"}
///   ]
/// }
/// ```
#[tracing::instrument(skip(state), fields(authzen_alias = true, search_type = "subject"))]
pub async fn post_search_subject(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    request: axum::Json<AuthZENSubjectSearchRequest>,
) -> Result<ResponseData<AuthZENSubjectSearchResponse>, ApiError> {
    let start = std::time::Instant::now();

    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, &[SCOPE_LIST])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            tenant_id = auth_ctx.organization,
            vault = %vault,
            "AuthZEN subject search request with authentication"
        );
    }

    // Validate required fields
    validate_authzen_subject_search_request(&request.0)?;

    // Convert AuthZEN request to native format with injection protection
    let resource = safe_format_entity(&request.0.resource.resource_type, &request.0.resource.id)?;
    let relation = request.0.action.name.clone();

    // Validate the generated resource string
    parse_entity(&resource)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid resource format: {}", e)))?;

    tracing::debug!(
        resource = %resource,
        relation = %relation,
        subject_type = ?request.0.subject_type,
        limit = ?request.0.limit,
        "Converted AuthZEN subject search request to native format"
    );

    // Convert to core request
    let list_request = ListSubjectsRequest {
        resource,
        relation,
        subject_type: request.0.subject_type,
        limit: request.0.limit.map(|l| l as usize),
        cursor: request.0.cursor,
    };

    // Execute the search operation using subject service
    let response = state.subject_service.list_subjects(vault, list_request).await?;

    // Convert native response to AuthZEN format
    let authzen_subjects: Result<Vec<AuthZENEntity>, ApiError> = response
        .subjects
        .iter()
        .map(|subject_str| {
            parse_entity(subject_str)
                .map_err(|e| ApiError::Internal(format!("Failed to parse subject: {}", e)))
        })
        .collect();

    let authzen_subjects = authzen_subjects?;

    // Record API request metric
    let duration = start.elapsed();
    inferadb_engine_observe::metrics::record_api_request(
        "/access/v1/search/subject",
        "POST",
        200,
        duration.as_secs_f64(),
    );

    tracing::info!(
        subject_count = response.subjects.len(),
        has_cursor = response.cursor.is_some(),
        duration_ms = duration.as_millis(),
        "AuthZEN subject search completed"
    );

    Ok(ResponseData::new(
        AuthZENSubjectSearchResponse { subjects: authzen_subjects, cursor: response.cursor },
        format,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use inferadb_engine_config::Config;
    use inferadb_engine_store::MemoryBackend;
    use inferadb_engine_types::Relationship;
    use tower::ServiceExt;

    use super::*;
    use crate::{AppState, test_utils::with_test_auth};

    async fn create_test_state() -> AppState {
        let store: Arc<dyn inferadb_engine_store::InferaStore> = Arc::new(MemoryBackend::new());

        // Create a schema with document type and view relation
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
                        subject: "user:alice".to_string(),
                    },
                    Relationship {
                        vault: test_vault,
                        resource: "document:secret".to_string(),
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

    #[tokio::test]
    async fn test_search_resource_basic() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "view".to_string() },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "charlie".to_string() },
            action: AuthZENAction { name: "view".to_string() },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "view".to_string() },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: AuthZENResourceSearchResponse = serde_json::from_slice(&body).unwrap();

        // Should only return 1 resource due to limit
        assert_eq!(json.resources.len(), 1);
    }

    #[tokio::test]
    async fn test_search_resource_empty_subject_type() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/resource", post(post_search_resource))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject { subject_type: "".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "view".to_string() },
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
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "".to_string() },
            action: AuthZENAction { name: "view".to_string() },
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
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "".to_string() },
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
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "view".to_string() },
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
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "User".to_string(), // Invalid: uppercase
                id: "alice".to_string(),
            },
            action: AuthZENAction { name: "view".to_string() },
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

    // Subject search tests

    #[tokio::test]
    async fn test_search_subject_basic() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction { name: "view".to_string() },
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: AuthZENSubjectSearchResponse = serde_json::from_slice(&body).unwrap();

        // Alice has view access to readme
        assert_eq!(json.subjects.len(), 1);
        assert_eq!(json.subjects[0].entity_type, "user");
        assert_eq!(json.subjects[0].id, "alice");
    }

    #[tokio::test]
    async fn test_search_subject_no_matches() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "nonexistent".to_string(),
            },
            action: AuthZENAction { name: "view".to_string() },
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: AuthZENSubjectSearchResponse = serde_json::from_slice(&body).unwrap();

        // No subjects have access to nonexistent document
        assert_eq!(json.subjects.len(), 0);
        assert!(json.cursor.is_none());
    }

    #[tokio::test]
    async fn test_search_subject_with_limit() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction { name: "view".to_string() },
            subject_type: None,
            limit: Some(10),
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: AuthZENSubjectSearchResponse = serde_json::from_slice(&body).unwrap();

        // Should return results within limit
        assert!(json.subjects.len() <= 10);
    }

    #[tokio::test]
    async fn test_search_subject_empty_resource_type() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource { resource_type: "".to_string(), id: "readme".to_string() },
            action: AuthZENAction { name: "view".to_string() },
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_subject_empty_resource_id() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource { resource_type: "document".to_string(), id: "".to_string() },
            action: AuthZENAction { name: "view".to_string() },
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_subject_empty_action() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction { name: "".to_string() },
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_subject_invalid_resource_format() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "Document".to_string(), // Invalid: uppercase
                id: "readme".to_string(),
            },
            action: AuthZENAction { name: "view".to_string() },
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_search_subject_with_subject_type_filter() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/search/subject", post(post_search_subject))
            .with_state(state.clone());
        let app = with_test_auth(app);

        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction { name: "view".to_string() },
            subject_type: Some("user".to_string()),
            limit: None,
            cursor: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/search/subject")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: AuthZENSubjectSearchResponse = serde_json::from_slice(&body).unwrap();

        // All returned subjects should be of type "user"
        for subject in &json.subjects {
            assert_eq!(subject.entity_type, "user");
        }
    }
}
