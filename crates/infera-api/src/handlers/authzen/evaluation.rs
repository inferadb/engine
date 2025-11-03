//! AuthZEN evaluation endpoints
//!
//! Implements the AuthZEN-compliant evaluation endpoints that provide a thin
//! adapter layer over InferaDB's native evaluation functionality.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use infera_const::scopes::*;
use infera_types::EvaluateRequest;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState,
    adapters::authzen::{AuthZENEvaluationRequest, convert_authzen_request_to_native},
    formatters::authzen::{format_denial_with_error, format_evaluation_response},
    handlers::utils::auth::authorize_request,
    validation::validate_authzen_evaluation_request,
};

/// Enhanced AuthZEN evaluation response with additional context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAuthZENEvaluationResponse {
    /// The authorization decision
    pub decision: bool,

    /// Evaluation context with unique ID and reasoning
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Handler for `POST /access/v1/evaluation`
///
/// This is a thin adapter that translates AuthZEN evaluation requests to
/// InferaDB's native format, performs the evaluation, and translates the
/// response back to AuthZEN format.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.check` scope
///
/// # AuthZEN Specification
///
/// Request format:
/// ```json
/// {
///   "subject": {"type": "user", "id": "alice"},
///   "action": {"name": "view"},
///   "resource": {"type": "document", "id": "readme"}
/// }
/// ```
///
/// Response format:
/// ```json
/// {
///   "decision": true,
///   "context": {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "reason_admin": {
///       "en": "user:alice has view permission on document:readme"
///     }
///   }
/// }
/// ```
#[tracing::instrument(skip(state), fields(authzen_alias = true))]
pub async fn post_evaluation(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<AuthZENEvaluationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let start = std::time::Instant::now();

    // Authorize request and extract vault
    let vault =
        authorize_request(&auth.0, state.default_vault, state.config.auth.enabled, &[SCOPE_CHECK])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            tenant_id = auth_ctx.tenant_id,
            vault = %vault,
            "AuthZEN evaluation request with authentication"
        );
    }

    // Validate required fields
    validate_authzen_evaluation_request(&request)?;

    // Convert AuthZEN request to native format
    let (subject, resource, permission) = convert_authzen_request_to_native(&request)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid entity format: {}", e)))?;

    tracing::debug!(
        subject = %subject,
        resource = %resource,
        permission = %permission,
        "Converted AuthZEN request to native format"
    );

    // Create evaluator with correct vault for this request
    use std::sync::Arc;
    let evaluator = Arc::new(infera_core::Evaluator::new(
        Arc::clone(&state.store) as Arc<dyn infera_store::RelationshipStore>,
        Arc::clone(state.evaluator.schema()),
        state.evaluator.wasm_host().cloned(),
        vault,
    ));

    // Create native evaluation request
    let native_request = EvaluateRequest {
        subject: subject.clone(),
        resource: resource.clone(),
        permission: permission.clone(),
        context: request.context.clone(),
        trace: Some(false),
    };

    // Perform evaluation using vault-scoped evaluator
    let decision = evaluator
        .check(native_request)
        .await
        .map_err(|e| ApiError::Internal(format!("Evaluation failed: {}", e)))?;

    // Format response using centralized formatter
    let response_value = format_evaluation_response(decision, &subject, &permission, &resource);

    // Convert to typed response
    let response: EnhancedAuthZENEvaluationResponse = serde_json::from_value(response_value)
        .map_err(|e| ApiError::Internal(format!("Failed to format response: {}", e)))?;

    // Record API request metric
    let duration = start.elapsed();
    infera_observe::metrics::record_api_request(
        "/access/v1/evaluation",
        "POST",
        200,
        duration.as_secs_f64(),
    );

    tracing::info!(
        decision = response.decision,
        evaluation_id =
            response.context.as_ref().and_then(|c| c.get("id")).and_then(|id| id.as_str()),
        duration_ms = duration.as_millis(),
        "AuthZEN evaluation completed"
    );

    Ok((StatusCode::OK, Json(response)))
}

/// Batch evaluation request containing multiple evaluations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENEvaluationsRequest {
    /// Array of evaluation requests
    pub evaluations: Vec<AuthZENEvaluationRequest>,
}

/// Batch evaluation response containing results for all evaluations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENEvaluationsResponse {
    /// Array of evaluation results, preserving input order
    pub evaluations: Vec<EnhancedAuthZENEvaluationResponse>,
}

/// Maximum number of evaluations allowed in a single batch request
const MAX_BATCH_SIZE: usize = 100;

/// Handler for `POST /access/v1/evaluations`
///
/// This is a batch evaluation endpoint that processes multiple authorization
/// checks in a single request. It translates AuthZEN batch requests to native
/// format, performs evaluations, and returns results in AuthZEN format.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.check` scope
///
/// # AuthZEN Specification
///
/// Request format:
/// ```json
/// {
///   "evaluations": [
///     {
///       "subject": {"type": "user", "id": "alice"},
///       "action": {"name": "view"},
///       "resource": {"type": "document", "id": "readme"}
///     },
///     {
///       "subject": {"type": "user", "id": "bob"},
///       "action": {"name": "edit"},
///       "resource": {"type": "document", "id": "spec"}
///     }
///   ]
/// }
/// ```
///
/// Response format:
/// ```json
/// {
///   "evaluations": [
///     {
///       "decision": true,
///       "context": {
///         "id": "550e8400-e29b-41d4-a716-446655440000",
///         "reason_admin": {"en": "..."}
///       }
///     },
///     {
///       "decision": false,
///       "context": {
///         "id": "660e8400-e29b-41d4-a716-446655440001",
///         "reason_admin": {"en": "..."}
///       }
///     }
///   ]
/// }
/// ```
///
/// # Batch Size Limits
///
/// Requests with more than 100 evaluations will be rejected with HTTP 400.
#[tracing::instrument(skip(state), fields(authzen_alias = true, batch = true))]
pub async fn post_evaluations(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<AuthZENEvaluationsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let start = std::time::Instant::now();
    let batch_size = request.evaluations.len();

    // Authorize request and extract vault
    let vault =
        authorize_request(&auth.0, state.default_vault, state.config.auth.enabled, &[SCOPE_CHECK])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            tenant_id = auth_ctx.tenant_id,
            vault = %vault,
            batch_size = batch_size,
            "AuthZEN batch evaluation request with authentication"
        );
    }

    // Validate batch size
    if batch_size == 0 {
        return Err(ApiError::InvalidRequest(
            "At least one evaluation must be provided".to_string(),
        ));
    }

    if batch_size > MAX_BATCH_SIZE {
        return Err(ApiError::InvalidRequest(format!(
            "Batch size {} exceeds maximum of {}",
            batch_size, MAX_BATCH_SIZE
        )));
    }

    // Create evaluator with correct vault for this request
    use std::sync::Arc;
    let evaluator = Arc::new(infera_core::Evaluator::new(
        Arc::clone(&state.store) as Arc<dyn infera_store::RelationshipStore>,
        Arc::clone(state.evaluator.schema()),
        state.evaluator.wasm_host().cloned(),
        vault,
    ));

    tracing::info!(batch_size = batch_size, vault = %vault, "Processing AuthZEN batch evaluation request");

    // Process each evaluation in the batch
    let mut results = Vec::with_capacity(batch_size);

    for (index, eval_request) in request.evaluations.into_iter().enumerate() {
        // Validate required fields for this evaluation
        if let Err(e) = validate_authzen_evaluation_request(&eval_request) {
            // On validation error, return a deny decision with error context
            let error_msg = format!("Validation error: {}", e);
            let response_value = format_denial_with_error(&error_msg);
            let response: EnhancedAuthZENEvaluationResponse =
                serde_json::from_value(response_value).unwrap();
            results.push(response);
            continue;
        }

        // Convert AuthZEN request to native format
        let conversion_result = convert_authzen_request_to_native(&eval_request);
        if let Err(e) = conversion_result {
            let error_msg = format!("Invalid entity format: {}", e);
            let response_value = format_denial_with_error(&error_msg);
            let response: EnhancedAuthZENEvaluationResponse =
                serde_json::from_value(response_value).unwrap();
            results.push(response);
            continue;
        }

        let (subject, resource, permission) = conversion_result.unwrap();

        // Create native evaluation request
        let native_request = EvaluateRequest {
            subject: subject.clone(),
            resource: resource.clone(),
            permission: permission.clone(),
            context: eval_request.context.clone(),
            trace: Some(false),
        };

        // Perform evaluation using vault-scoped evaluator
        let decision_result = evaluator.check(native_request).await;

        match decision_result {
            Ok(decision) => {
                // Format response using centralized formatter
                let response_value =
                    format_evaluation_response(decision, &subject, &permission, &resource);
                let response: EnhancedAuthZENEvaluationResponse =
                    serde_json::from_value(response_value).unwrap();

                tracing::debug!(
                    evaluation_index = index,
                    decision = response.decision,
                    "Completed evaluation in batch"
                );

                results.push(response);
            },
            Err(e) => {
                // On evaluation error, return deny with error context
                let error_msg = format!("Evaluation error: {}", e);
                let response_value = format_denial_with_error(&error_msg);
                let response: EnhancedAuthZENEvaluationResponse =
                    serde_json::from_value(response_value).unwrap();

                tracing::debug!(
                    evaluation_index = index,
                    decision = false,
                    error = %e,
                    "Evaluation failed in batch"
                );

                results.push(response);
            },
        }
    }

    // Record metrics
    let duration = start.elapsed();
    infera_observe::metrics::record_api_request(
        "/access/v1/evaluations",
        "POST",
        200,
        duration.as_secs_f64(),
    );

    tracing::info!(
        batch_size = batch_size,
        duration_ms = duration.as_millis(),
        "AuthZEN batch evaluation completed"
    );

    let response = AuthZENEvaluationsResponse { evaluations: results };

    Ok((StatusCode::OK, Json(response)))
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
    use infera_config::Config;
    use infera_core::Evaluator;
    use infera_store::MemoryBackend;
    use infera_types::Relationship;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::{
        AppState,
        adapters::authzen::{AuthZENAction, AuthZENResource, AuthZENSubject},
    };

    async fn create_test_state() -> AppState {
        let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());

        // Create a schema with document type and view/delete relations
        use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![
                RelationDef { name: "view".to_string(), expr: Some(RelationExpr::This) },
                RelationDef { name: "delete".to_string(), expr: Some(RelationExpr::This) },
            ],
            forbids: vec![],
        }]));

        // Use a test vault ID
        let test_vault = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let evaluator = Arc::new(Evaluator::new(
            Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>,
            schema,
            None,
            test_vault,
        ));
        let config = Arc::new(Config::default());
        let health_tracker = Arc::new(crate::health::HealthTracker::new());

        // Add a test relationship: user:alice can view document:readme
        store
            .write(
                test_vault,
                vec![Relationship {
                    vault: test_vault,
                    subject: "user:alice".to_string(),
                    relation: "view".to_string(),
                    resource: "document:readme".to_string(),
                }],
            )
            .await
            .unwrap();

        AppState {
            evaluator,
            store,
            config,
            jwks_cache: None,
            health_tracker,
            default_vault: test_vault,
            default_account: Uuid::nil(),
        }
    }

    #[tokio::test]
    async fn test_evaluation_allow() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluation", post(post_evaluation)).with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "view".to_string() },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: EnhancedAuthZENEvaluationResponse = serde_json::from_slice(&body).unwrap();

        assert!(response.decision);
        assert!(response.context.is_some());

        let context = response.context.unwrap();
        assert!(context["id"].is_string());
        assert_eq!(
            context["reason_admin"]["en"].as_str().unwrap(),
            "user:alice has view permission on document:readme"
        );
    }

    #[tokio::test]
    async fn test_evaluation_deny() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluation", post(post_evaluation)).with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "bob".to_string() },
            action: AuthZENAction { name: "delete".to_string() },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() != StatusCode::OK {
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            eprintln!("Error response body: {}", String::from_utf8_lossy(&body));
            panic!("Expected 200 OK, got {}", status);
        }

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: EnhancedAuthZENEvaluationResponse = serde_json::from_slice(&body).unwrap();

        assert!(!response.decision);
        assert!(response.context.is_some());

        let context = response.context.unwrap();
        assert!(context["id"].is_string());
        assert_eq!(
            context["reason_admin"]["en"].as_str().unwrap(),
            "user:bob does not have delete permission on document:readme"
        );
    }

    #[tokio::test]
    async fn test_evaluation_missing_subject_type() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluation", post(post_evaluation)).with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject { subject_type: "".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "view".to_string() },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_evaluation_missing_action_name() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluation", post(post_evaluation)).with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "".to_string() },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_evaluation_invalid_entity_format() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluation", post(post_evaluation)).with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "User".to_string(), // Invalid: uppercase not allowed
                id: "alice".to_string(),
            },
            action: AuthZENAction { name: "view".to_string() },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_evaluation_response_structure() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluation", post(post_evaluation)).with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject { subject_type: "user".to_string(), id: "alice".to_string() },
            action: AuthZENAction { name: "view".to_string() },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify structure
        assert!(json["decision"].is_boolean());
        assert!(json["context"].is_object());
        assert!(json["context"]["id"].is_string());
        assert!(json["context"]["reason_admin"].is_object());
        assert!(json["context"]["reason_admin"]["en"].is_string());
    }

    // Batch evaluation tests

    #[tokio::test]
    async fn test_batch_evaluation_single() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluations", post(post_evaluations)).with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![AuthZENEvaluationRequest {
                subject: AuthZENSubject {
                    subject_type: "user".to_string(),
                    id: "alice".to_string(),
                },
                action: AuthZENAction { name: "view".to_string() },
                resource: AuthZENResource {
                    resource_type: "document".to_string(),
                    id: "readme".to_string(),
                },
                context: None,
            }],
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluations")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.evaluations.len(), 1);
        assert!(response.evaluations[0].decision);
    }

    #[tokio::test]
    async fn test_batch_evaluation_multiple() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluations", post(post_evaluations)).with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction { name: "view".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "bob".to_string(),
                    },
                    action: AuthZENAction { name: "delete".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction { name: "delete".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
            ],
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluations")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.evaluations.len(), 3);
        assert!(response.evaluations[0].decision); // alice can view
        assert!(!response.evaluations[1].decision); // bob cannot delete
        assert!(!response.evaluations[2].decision); // alice cannot delete
    }

    #[tokio::test]
    async fn test_batch_evaluation_empty() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluations", post(post_evaluations)).with_state(state);

        let request_body = AuthZENEvaluationsRequest { evaluations: vec![] };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluations")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_batch_evaluation_over_limit() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluations", post(post_evaluations)).with_state(state);

        // Create 101 evaluations (over the limit of 100)
        let mut evaluations = Vec::new();
        for i in 0..101 {
            evaluations.push(AuthZENEvaluationRequest {
                subject: AuthZENSubject {
                    subject_type: "user".to_string(),
                    id: format!("user{}", i),
                },
                action: AuthZENAction { name: "view".to_string() },
                resource: AuthZENResource {
                    resource_type: "document".to_string(),
                    id: "readme".to_string(),
                },
                context: None,
            });
        }

        let request_body = AuthZENEvaluationsRequest { evaluations };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluations")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_batch_evaluation_partial_failures() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluations", post(post_evaluations)).with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction { name: "view".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "".to_string(), // Invalid: empty type
                        id: "bob".to_string(),
                    },
                    action: AuthZENAction { name: "view".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "User".to_string(), // Invalid: uppercase
                        id: "charlie".to_string(),
                    },
                    action: AuthZENAction { name: "view".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
            ],
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluations")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.evaluations.len(), 3);
        assert!(response.evaluations[0].decision); // Valid request
        assert!(!response.evaluations[1].decision); // Validation error
        assert!(!response.evaluations[2].decision); // Invalid format

        // Check that errors are included in context
        let context1 = &response.evaluations[1].context.as_ref().unwrap();
        assert!(context1["error"].is_string());

        let context2 = &response.evaluations[2].context.as_ref().unwrap();
        assert!(context2["error"].is_string());
    }

    #[tokio::test]
    async fn test_batch_evaluation_preserves_order() {
        let state = create_test_state().await;

        let app =
            Router::new().route("/access/v1/evaluations", post(post_evaluations)).with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction { name: "view".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "bob".to_string(),
                    },
                    action: AuthZENAction { name: "view".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction { name: "delete".to_string() },
                    resource: AuthZENResource {
                        resource_type: "document".to_string(),
                        id: "readme".to_string(),
                    },
                    context: None,
                },
            ],
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluations")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        // Verify order is preserved
        assert!(response.evaluations[0].decision); // alice view
        assert!(!response.evaluations[1].decision); // bob view (no permission)
        assert!(!response.evaluations[2].decision); // alice delete
    }
}
