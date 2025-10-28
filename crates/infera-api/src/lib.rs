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

use infera_core::{CheckRequest, Decision, Evaluator};
use infera_config::Config;

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
    pub config: Arc<Config>,
}

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/check", post(check_handler))
        .route("/expand", post(expand_handler))
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
    Json(request): Json<infera_core::ExpandRequest>,
) -> Result<Json<infera_core::UsersetTree>> {
    let tree = state.evaluator.expand(request).await?;
    Ok(Json(tree))
}

/// Start the API server
pub async fn serve(evaluator: Arc<Evaluator>, config: Arc<Config>) -> anyhow::Result<()> {
    let state = AppState { evaluator, config: config.clone() };
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

    #[test]
    fn test_api_module() {
        // Placeholder test
        assert!(true);
    }
}
