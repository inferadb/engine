//! # Infera API - REST and gRPC API Layer
//!
//! Exposes REST and gRPC endpoints for authorization checks (AuthZEN-compatible).

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use infera_core::{CheckRequest, Decision, Evaluator, ExpandRequest};
use infera_config::Config;
use infera_store::{Tuple, Revision, TupleStore};

pub mod routes;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Evaluation error: {0}")]
    Evaluation(#[from] infera_core::EvalError),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Evaluation(_) => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub type Result<T> = std::result::Result<T, ApiError>;

/// Application state
#[derive(Clone)]
pub struct AppState {
    pub evaluator: Arc<Evaluator>,
    pub store: Arc<dyn TupleStore>,
    pub config: Arc<Config>,
}

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/check", post(check_handler))
        .route("/expand", post(expand_handler))
        .route("/write", post(write_handler))
        .with_state(state)
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "inferadb"
    }))
}

/// Authorization check endpoint
async fn check_handler(
    State(state): State<AppState>,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>> {
    let decision = state.evaluator.check(request).await?;

    Ok(Json(CheckResponse {
        decision: match decision {
            Decision::Allow => "allow".to_string(),
            Decision::Deny => "deny".to_string(),
        },
    }))
}

#[derive(Serialize, Deserialize)]
struct CheckResponse {
    decision: String,
}

/// Expand endpoint
async fn expand_handler(
    State(state): State<AppState>,
    Json(request): Json<ExpandRequest>,
) -> Result<Json<infera_core::UsersetTree>> {
    let tree = state.evaluator.expand(request).await?;
    Ok(Json(tree))
}

/// Write tuples endpoint
async fn write_handler(
    State(state): State<AppState>,
    Json(request): Json<WriteRequest>,
) -> Result<Json<WriteResponse>> {
    // Validate request
    if request.tuples.is_empty() {
        return Err(ApiError::InvalidRequest("No tuples provided".to_string()));
    }

    // Validate tuple format
    for tuple in &request.tuples {
        if tuple.object.is_empty() {
            return Err(ApiError::InvalidRequest("Tuple object cannot be empty".to_string()));
        }
        if tuple.relation.is_empty() {
            return Err(ApiError::InvalidRequest("Tuple relation cannot be empty".to_string()));
        }
        if tuple.user.is_empty() {
            return Err(ApiError::InvalidRequest("Tuple user cannot be empty".to_string()));
        }
        // Validate format (should contain colon)
        if !tuple.object.contains(':') {
            return Err(ApiError::InvalidRequest(format!("Invalid object format '{}': must be 'type:id'", tuple.object)));
        }
        if !tuple.user.contains(':') {
            return Err(ApiError::InvalidRequest(format!("Invalid user format '{}': must be 'type:id'", tuple.user)));
        }
    }

    // Write tuples to store
    let revision = state.store.write(request.tuples.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write tuples: {}", e)))?;

    Ok(Json(WriteResponse {
        revision: revision.0.to_string(), // Extract the u64 value
        tuples_written: request.tuples.len(),
    }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteRequest {
    pub tuples: Vec<Tuple>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteResponse {
    pub revision: String,
    pub tuples_written: usize,
}

/// Start the API server
pub async fn serve(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn TupleStore>,
    config: Arc<Config>,
) -> anyhow::Result<()> {
    let state = AppState {
        evaluator,
        store,
        config: config.clone(),
    };
    let app = create_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use infera_core::ipl::{Schema, TypeDef, RelationDef, RelationExpr};
    use infera_store::MemoryBackend;
    use serde_json::json;
    use tower::ServiceExt; // for `oneshot`

    fn create_test_state() -> AppState {
        let store: Arc<dyn TupleStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("editor".to_string(), Some(RelationExpr::Union(vec![
                    RelationExpr::This,
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                ]))),
            ]),
        ]));
        let evaluator = Arc::new(Evaluator::new(Arc::clone(&store), schema, None));
        let config = Arc::new(infera_config::Config::default());

        AppState {
            evaluator,
            store,
            config,
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_check_deny() {
        let app = create_router(create_test_state());

        let request_body = json!({
            "subject": "user:alice",
            "resource": "doc:readme",
            "permission": "reader",
            "context": null
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/check")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_json["decision"], "deny");
    }

    #[tokio::test]
    async fn test_write_and_check() {
        let state = create_test_state();
        let app = create_router(state.clone());

        // First, write a tuple
        let write_request = json!({
            "tuples": [{
                "object": "doc:readme",
                "relation": "reader",
                "user": "user:alice"
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let write_response: WriteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(write_response.tuples_written, 1);

        // Now check the permission
        let check_request = json!({
            "subject": "user:alice",
            "resource": "doc:readme",
            "permission": "reader",
            "context": null
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/check")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&check_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let check_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(check_response["decision"], "allow");
    }

    #[tokio::test]
    async fn test_write_validation_empty_tuples() {
        let app = create_router(create_test_state());

        let write_request = json!({
            "tuples": []
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_write_validation_invalid_object_format() {
        let app = create_router(create_test_state());

        let write_request = json!({
            "tuples": [{
                "object": "invalid",  // Missing colon
                "relation": "reader",
                "user": "user:alice"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_expand() {
        let app = create_router(create_test_state());

        let expand_request = json!({
            "resource": "doc:readme",
            "relation": "editor"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/expand")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&expand_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let tree: infera_core::UsersetTree = serde_json::from_slice(&body).unwrap();
        assert!(matches!(tree.node_type, infera_core::UsersetNodeType::Union));
    }
}
