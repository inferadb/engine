//! # Infera API - REST and gRPC API Layer
//!
//! Exposes REST and gRPC endpoints for authorization checks (AuthZEN-compatible).

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use infera_auth::jwks_cache::JwksCache;
use infera_core::{CheckRequest, Decision, Evaluator, ExpandRequest};
use infera_config::Config;
use infera_store::{Tuple, TupleStore};

pub mod routes;
pub mod grpc;
pub mod grpc_interceptor;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Evaluation error: {0}")]
    Evaluation(#[from] infera_core::EvalError),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),

    // Authentication errors
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Unknown tenant: {0}")]
    UnknownTenant(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, headers) = match self {
            ApiError::Evaluation(_) => (StatusCode::FORBIDDEN, self.to_string(), None),
            ApiError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string(), None),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string(), None),

            // Authentication errors with WWW-Authenticate header
            ApiError::Unauthorized(_) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"InferaDB\""),
                );
                (StatusCode::UNAUTHORIZED, self.to_string(), Some(headers))
            },
            ApiError::InvalidTokenFormat(_) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"InferaDB\", error=\"invalid_token\""),
                );
                (StatusCode::UNAUTHORIZED, self.to_string(), Some(headers))
            },
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string(), None),
            ApiError::UnknownTenant(_) => (StatusCode::NOT_FOUND, self.to_string(), None),
        };

        let mut response = (status, Json(ErrorResponse { error: message })).into_response();
        if let Some(h) = headers {
            response.headers_mut().extend(h);
        }
        response
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
    pub jwks_cache: Option<Arc<JwksCache>>,
}

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    // Protected routes that require authentication
    let protected_routes = Router::new()
        .route("/check", post(check_handler))
        .route("/expand", post(expand_handler))
        .route("/write", post(write_handler));

    // Apply authentication middleware if enabled and JWKS cache is available
    let protected_routes = if state.config.auth.enabled {
        if let Some(jwks_cache) = &state.jwks_cache {
            info!("Authentication ENABLED - applying auth middleware to protected routes");
            let jwks_cache = Arc::clone(jwks_cache);
            let auth_enabled = state.config.auth.enabled;

            protected_routes.layer(axum::middleware::from_fn(move |req, next| {
                let jwks_cache = Arc::clone(&jwks_cache);
                infera_auth::middleware::optional_auth_middleware(auth_enabled, jwks_cache, req, next)
            }))
        } else {
            tracing::warn!("Authentication ENABLED but JWKS cache not initialized - skipping auth");
            protected_routes
        }
    } else {
        tracing::warn!("Authentication DISABLED - requests will not be authenticated");
        protected_routes
    };

    // Combine health (unprotected) with protected routes
    Router::new()
        .route("/health", get(health_check))
        .merge(protected_routes)
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
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope
            infera_auth::middleware::require_scope(&auth_ctx, "inferadb.check")
                .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            // TODO: Add tenant isolation check when we have multi-tenant support
            // For now, we just log the authenticated tenant
            tracing::debug!("Check request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized("Authentication required".to_string()));
        }
    }

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
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ExpandRequest>,
) -> Result<Json<infera_core::ExpandResponse>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.expand scope (or check scope as fallback)
            infera_auth::middleware::require_any_scope(&auth_ctx, &["inferadb.expand", "inferadb.check"])
                .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Expand request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized("Authentication required".to_string()));
        }
    }

    let response = state.evaluator.expand(request).await?;
    Ok(Json(response))
}

/// Write tuples endpoint
async fn write_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<WriteRequest>,
) -> Result<Json<WriteResponse>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.write scope
            infera_auth::middleware::require_scope(&auth_ctx, "inferadb.write")
                .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Write request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized("Authentication required".to_string()));
        }
    }

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

/// Start the REST API server
pub async fn serve(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn TupleStore>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
) -> anyhow::Result<()> {
    let state = AppState {
        evaluator,
        store,
        config: config.clone(),
        jwks_cache,
    };
    let app = create_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting REST API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Start the gRPC server
pub async fn serve_grpc(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn TupleStore>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
) -> anyhow::Result<()> {
    use tonic::transport::Server;
    use grpc::proto::infera_service_server::InferaServiceServer;

    let state = AppState {
        evaluator,
        store,
        config: config.clone(),
        jwks_cache: jwks_cache.clone(),
    };

    let service = grpc::InferaServiceImpl::new(state);

    // Use port + 1 for gRPC by default
    let grpc_port = config.server.port + 1;
    let addr = format!("{}:{}", config.server.host, grpc_port).parse()?;

    // Set up authentication if enabled
    if config.auth.enabled {
        if let Some(cache) = jwks_cache {
            info!("Starting gRPC server on {} with authentication enabled", addr);

            // Try to load internal JWKS if configured
            let internal_loader = infera_auth::InternalJwksLoader::from_config(
                config.auth.internal_jwks_path.as_deref(),
                config.auth.internal_jwks_env.as_deref(),
            )
            .ok()
            .map(Arc::new);

            if internal_loader.is_some() {
                info!("Internal JWT authentication enabled for gRPC");
            }

            // Create auth interceptor
            let interceptor = grpc_interceptor::AuthInterceptor::new(
                cache,
                internal_loader,
                Arc::new(config.auth.clone()),
            );

            // Add service with interceptor
            Server::builder()
                .add_service(InferaServiceServer::with_interceptor(service, interceptor))
                .serve(addr)
                .await?;
        } else {
            return Err(anyhow::anyhow!(
                "Authentication enabled but JWKS cache not initialized"
            ));
        }
    } else {
        info!("Starting gRPC server on {} WITHOUT authentication", addr);
        tracing::warn!("gRPC authentication is DISABLED - use only in development/testing");

        Server::builder()
            .add_service(InferaServiceServer::new(service))
            .serve(addr)
            .await?;
    }

    Ok(())
}

/// Start both REST and gRPC servers concurrently
pub async fn serve_both(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn TupleStore>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
) -> anyhow::Result<()> {
    let rest_evaluator = Arc::clone(&evaluator);
    let rest_store = Arc::clone(&store);
    let rest_config = Arc::clone(&config);
    let rest_jwks_cache = jwks_cache.as_ref().map(Arc::clone);

    let grpc_evaluator = Arc::clone(&evaluator);
    let grpc_store = Arc::clone(&store);
    let grpc_config = Arc::clone(&config);
    let grpc_jwks_cache = jwks_cache.as_ref().map(Arc::clone);

    tokio::try_join!(
        serve(rest_evaluator, rest_store, rest_config, rest_jwks_cache),
        serve_grpc(grpc_evaluator, grpc_store, grpc_config, grpc_jwks_cache),
    )?;

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
        let mut config = infera_config::Config::default();
        // Disable auth for tests by default
        config.auth.enabled = false;
        let config = Arc::new(config);

        AppState {
            evaluator,
            store,
            config,
            jwks_cache: None,
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
        let expand_response: infera_core::ExpandResponse = serde_json::from_slice(&body).unwrap();
        assert!(matches!(expand_response.tree.node_type, infera_core::UsersetNodeType::Union));
    }
}
