//! AuthZEN evaluation endpoints
//!
//! Implements the AuthZEN-compliant evaluation endpoints that provide a thin
//! adapter layer over InferaDB's native evaluation functionality.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::adapters::authzen::{convert_authzen_request_to_native, AuthZENEvaluationRequest};
use crate::validation::validate_authzen_evaluation_request;
use crate::ApiError;
use crate::AppState;
use infera_types::{Decision, EvaluateRequest};

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
    State(state): State<AppState>,
    Json(request): Json<AuthZENEvaluationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let start = std::time::Instant::now();

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

    // Create native evaluation request
    let native_request = EvaluateRequest {
        subject: subject.clone(),
        resource: resource.clone(),
        permission: permission.clone(),
        context: request.context.clone(),
        trace: Some(false),
    };

    // Perform evaluation using native evaluator
    let decision = state
        .evaluator
        .check(native_request)
        .await
        .map_err(|e| ApiError::Internal(format!("Evaluation failed: {}", e)))?;

    // Convert decision to boolean
    let decision_bool = matches!(decision, Decision::Allow);

    // Generate unique evaluation ID
    let evaluation_id = Uuid::new_v4();

    // Create human-readable reason
    let reason = if decision_bool {
        format!("{} has {} permission on {}", subject, permission, resource)
    } else {
        format!(
            "{} does not have {} permission on {}",
            subject, permission, resource
        )
    };

    // Build response with context
    let response = EnhancedAuthZENEvaluationResponse {
        decision: decision_bool,
        context: Some(json!({
            "id": evaluation_id.to_string(),
            "reason_admin": {
                "en": reason
            }
        })),
    };

    // Record API request metric
    let duration = start.elapsed();
    infera_observe::metrics::record_api_request(
        "/access/v1/evaluation",
        "POST",
        200,
        duration.as_secs_f64(),
    );

    tracing::info!(
        decision = decision_bool,
        evaluation_id = %evaluation_id,
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
    State(state): State<AppState>,
    Json(request): Json<AuthZENEvaluationsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let start = std::time::Instant::now();
    let batch_size = request.evaluations.len();

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

    tracing::info!(
        batch_size = batch_size,
        "Processing AuthZEN batch evaluation request"
    );

    // Process each evaluation in the batch
    let mut results = Vec::with_capacity(batch_size);

    for (index, eval_request) in request.evaluations.into_iter().enumerate() {
        // Validate required fields for this evaluation
        if let Err(e) = validate_authzen_evaluation_request(&eval_request) {
            // On validation error, return a deny decision with error context
            let evaluation_id = Uuid::new_v4();
            let error_msg = e.to_string();
            results.push(EnhancedAuthZENEvaluationResponse {
                decision: false,
                context: Some(json!({
                    "id": evaluation_id.to_string(),
                    "reason_admin": {
                        "en": format!("Validation error: {}", error_msg)
                    },
                    "error": error_msg
                })),
            });
            continue;
        }

        // Convert AuthZEN request to native format
        let conversion_result = convert_authzen_request_to_native(&eval_request);
        if let Err(e) = conversion_result {
            let evaluation_id = Uuid::new_v4();
            results.push(EnhancedAuthZENEvaluationResponse {
                decision: false,
                context: Some(json!({
                    "id": evaluation_id.to_string(),
                    "reason_admin": {
                        "en": format!("Invalid entity format: {}", e)
                    },
                    "error": format!("Invalid entity format: {}", e)
                })),
            });
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

        // Perform evaluation
        let decision_result = state.evaluator.check(native_request).await;

        let evaluation_id = Uuid::new_v4();

        match decision_result {
            Ok(decision) => {
                let decision_bool = matches!(decision, Decision::Allow);

                let reason = if decision_bool {
                    format!("{} has {} permission on {}", subject, permission, resource)
                } else {
                    format!(
                        "{} does not have {} permission on {}",
                        subject, permission, resource
                    )
                };

                results.push(EnhancedAuthZENEvaluationResponse {
                    decision: decision_bool,
                    context: Some(json!({
                        "id": evaluation_id.to_string(),
                        "reason_admin": {
                            "en": reason
                        }
                    })),
                });
            }
            Err(e) => {
                // On evaluation error, return deny with error context
                results.push(EnhancedAuthZENEvaluationResponse {
                    decision: false,
                    context: Some(json!({
                        "id": evaluation_id.to_string(),
                        "reason_admin": {
                            "en": format!("Evaluation error: {}", e)
                        },
                        "error": format!("Evaluation error: {}", e)
                    })),
                });
            }
        }

        tracing::debug!(
            evaluation_index = index,
            evaluation_id = %evaluation_id,
            "Completed evaluation in batch"
        );
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

    let response = AuthZENEvaluationsResponse {
        evaluations: results,
    };

    Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::authzen::{AuthZENAction, AuthZENResource, AuthZENSubject};
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

        // Create a schema with document type and view/delete relations
        use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![
                RelationDef {
                    name: "view".to_string(),
                    expr: Some(RelationExpr::This),
                },
                RelationDef {
                    name: "delete".to_string(),
                    expr: Some(RelationExpr::This),
                },
            ],
            forbids: vec![],
        }]));

        let evaluator = Arc::new(Evaluator::new(Arc::clone(&store), schema, None));
        let config = Arc::new(Config::default());
        let health_tracker = Arc::new(crate::health::HealthTracker::new());

        // Add a test relationship: user:alice can view document:readme
        store
            .write(vec![Relationship {
                subject: "user:alice".to_string(),
                relation: "view".to_string(),
                resource: "document:readme".to_string(),
            }])
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
    async fn test_evaluation_allow() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/evaluation", post(post_evaluation))
            .with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: EnhancedAuthZENEvaluationResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.decision, true);
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

        let app = Router::new()
            .route("/access/v1/evaluation", post(post_evaluation))
            .with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "bob".to_string(),
            },
            action: AuthZENAction {
                name: "delete".to_string(),
            },
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
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            eprintln!("Error response body: {}", String::from_utf8_lossy(&body));
            panic!("Expected 200 OK, got {}", status);
        }

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: EnhancedAuthZENEvaluationResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.decision, false);
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

        let app = Router::new()
            .route("/access/v1/evaluation", post(post_evaluation))
            .with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
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

        let app = Router::new()
            .route("/access/v1/evaluation", post(post_evaluation))
            .with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "".to_string(),
            },
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

        let app = Router::new()
            .route("/access/v1/evaluation", post(post_evaluation))
            .with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "User".to_string(), // Invalid: uppercase not allowed
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
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

        let app = Router::new()
            .route("/access/v1/evaluation", post(post_evaluation))
            .with_state(state);

        let request_body = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let app = Router::new()
            .route("/access/v1/evaluations", post(post_evaluations))
            .with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![AuthZENEvaluationRequest {
                subject: AuthZENSubject {
                    subject_type: "user".to_string(),
                    id: "alice".to_string(),
                },
                action: AuthZENAction {
                    name: "view".to_string(),
                },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.evaluations.len(), 1);
        assert_eq!(response.evaluations[0].decision, true);
    }

    #[tokio::test]
    async fn test_batch_evaluation_multiple() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/evaluations", post(post_evaluations))
            .with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction {
                        name: "view".to_string(),
                    },
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
                    action: AuthZENAction {
                        name: "delete".to_string(),
                    },
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
                    action: AuthZENAction {
                        name: "delete".to_string(),
                    },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.evaluations.len(), 3);
        assert_eq!(response.evaluations[0].decision, true); // alice can view
        assert_eq!(response.evaluations[1].decision, false); // bob cannot delete
        assert_eq!(response.evaluations[2].decision, false); // alice cannot delete
    }

    #[tokio::test]
    async fn test_batch_evaluation_empty() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/evaluations", post(post_evaluations))
            .with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![],
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_batch_evaluation_over_limit() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/evaluations", post(post_evaluations))
            .with_state(state);

        // Create 101 evaluations (over the limit of 100)
        let mut evaluations = Vec::new();
        for i in 0..101 {
            evaluations.push(AuthZENEvaluationRequest {
                subject: AuthZENSubject {
                    subject_type: "user".to_string(),
                    id: format!("user{}", i),
                },
                action: AuthZENAction {
                    name: "view".to_string(),
                },
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

        let app = Router::new()
            .route("/access/v1/evaluations", post(post_evaluations))
            .with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction {
                        name: "view".to_string(),
                    },
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
                    action: AuthZENAction {
                        name: "view".to_string(),
                    },
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
                    action: AuthZENAction {
                        name: "view".to_string(),
                    },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response.evaluations.len(), 3);
        assert_eq!(response.evaluations[0].decision, true); // Valid request
        assert_eq!(response.evaluations[1].decision, false); // Validation error
        assert_eq!(response.evaluations[2].decision, false); // Invalid format

        // Check that errors are included in context
        let context1 = &response.evaluations[1].context.as_ref().unwrap();
        assert!(context1["error"].is_string());

        let context2 = &response.evaluations[2].context.as_ref().unwrap();
        assert!(context2["error"].is_string());
    }

    #[tokio::test]
    async fn test_batch_evaluation_preserves_order() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/access/v1/evaluations", post(post_evaluations))
            .with_state(state);

        let request_body = AuthZENEvaluationsRequest {
            evaluations: vec![
                AuthZENEvaluationRequest {
                    subject: AuthZENSubject {
                        subject_type: "user".to_string(),
                        id: "alice".to_string(),
                    },
                    action: AuthZENAction {
                        name: "view".to_string(),
                    },
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
                    action: AuthZENAction {
                        name: "view".to_string(),
                    },
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
                    action: AuthZENAction {
                        name: "delete".to_string(),
                    },
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: AuthZENEvaluationsResponse = serde_json::from_slice(&body).unwrap();

        // Verify order is preserved
        assert_eq!(response.evaluations[0].decision, true); // alice view
        assert_eq!(response.evaluations[1].decision, false); // bob view (no permission)
        assert_eq!(response.evaluations[2].decision, false); // alice delete
    }
}
