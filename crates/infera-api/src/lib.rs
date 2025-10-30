//! # Infera API - REST and gRPC API Layer
//!
//! Exposes REST and gRPC endpoints for authorization checks (AuthZEN-compatible).

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures::stream::{self, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{compression::CompressionLayer, cors::CorsLayer};
use tracing::info;

use infera_auth::jwks_cache::JwksCache;
use infera_config::Config;
use infera_core::{CheckRequest, Decision, Evaluator, ExpandRequest};
use infera_store::{Tuple, TupleStore};

pub mod grpc;
pub mod grpc_interceptor;
pub mod health;
pub mod routes;

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

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Revision mismatch: expected {expected}, got {actual}")]
    RevisionMismatch { expected: String, actual: String },
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
            }
            ApiError::InvalidTokenFormat(_) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"InferaDB\", error=\"invalid_token\""),
                );
                (StatusCode::UNAUTHORIZED, self.to_string(), Some(headers))
            }
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string(), None),
            ApiError::UnknownTenant(_) => (StatusCode::NOT_FOUND, self.to_string(), None),

            // Rate limit error with Retry-After header
            ApiError::RateLimitExceeded => {
                let mut headers = HeaderMap::new();
                headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                headers.insert("x-ratelimit-limit", HeaderValue::from_static("1000"));
                headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    self.to_string(),
                    Some(headers),
                )
            }

            // Optimistic locking conflict
            ApiError::RevisionMismatch { .. } => (StatusCode::CONFLICT, self.to_string(), None),
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
    pub health_tracker: Arc<health::HealthTracker>,
}

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    // Configure rate limiting: 1000 requests per minute per IP
    // Based on docs/RATE_LIMITING.md recommendations
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1000 / 60) // 1000 requests per minute = ~16.67 per second
            .burst_size(2000) // Allow bursts up to 2000 requests
            .use_headers() // Add rate limit headers to responses
            .finish()
            .unwrap(),
    );

    let governor_layer = GovernorLayer {
        config: governor_conf,
    };

    // Protected routes that require authentication
    let protected_routes = Router::new()
        .route("/check", post(check_handler))
        .route("/expand", post(expand_handler))
        .route("/expand/stream", post(expand_stream_handler))
        .route("/write", post(write_handler))
        .route("/delete", post(delete_handler))
        .route("/simulate", post(simulate_handler))
        .route("/explain", post(explain_handler));

    // Apply authentication middleware if enabled and JWKS cache is available
    let protected_routes = if state.config.auth.enabled {
        if let Some(jwks_cache) = &state.jwks_cache {
            info!("Authentication ENABLED - applying auth middleware to protected routes");
            let jwks_cache = Arc::clone(jwks_cache);
            let auth_enabled = state.config.auth.enabled;

            protected_routes.layer(axum::middleware::from_fn(move |req, next| {
                let jwks_cache = Arc::clone(&jwks_cache);
                infera_auth::middleware::optional_auth_middleware(
                    auth_enabled,
                    jwks_cache,
                    req,
                    next,
                )
            }))
        } else {
            tracing::warn!("Authentication ENABLED but JWKS cache not initialized - skipping auth");
            protected_routes
        }
    } else {
        tracing::warn!("Authentication DISABLED - requests will not be authenticated");
        protected_routes
    };

    // Combine health endpoints (unprotected) with protected routes
    let router = Router::new()
        .route("/health", get(health::health_check_handler))
        .route("/health/live", get(health::liveness_handler))
        .route("/health/ready", get(health::readiness_handler))
        .route("/health/startup", get(health::startup_handler))
        .merge(protected_routes)
        .with_state(state.clone());

    // Add CORS, compression, and rate limiting layers
    // Note: Rate limiting is applied to all routes except /health (which is separate)
    let router = router
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .layer(CompressionLayer::new());

    // Add rate limiting if enabled
    if state.config.server.rate_limiting_enabled {
        info!("Rate limiting ENABLED - applying governor layer");
        router.layer(governor_layer)
    } else {
        info!("Rate limiting DISABLED - skipping governor layer");
        router
    }
}

// Health check handlers moved to health.rs module

/// Graceful shutdown signal handler
///
/// Waits for SIGTERM (Kubernetes) or SIGINT (Ctrl+C) and initiates graceful shutdown.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C), initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }

    info!("Shutdown signal received, draining connections...");
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
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
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
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &["inferadb.expand", "inferadb.check"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Expand request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    let response = state.evaluator.expand(request).await?;
    Ok(Json(response))
}

/// Streaming expand endpoint using Server-Sent Events
///
/// Returns users as they're discovered, enabling progressive rendering
/// for large result sets.
async fn expand_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ExpandRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.expand scope (or check scope as fallback)
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &["inferadb.expand", "inferadb.check"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!(
                "Streaming expand request from tenant: {}",
                auth_ctx.tenant_id
            );
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Execute the expand operation
    let response = state.evaluator.expand(request).await?;

    // Create a stream that sends each user as a separate SSE event
    let users = response.users;
    let tree = response.tree;
    let continuation_token = response.continuation_token;
    let total_count = response.total_count;

    let stream = stream::iter(users.into_iter().enumerate().map(|(idx, user)| {
        let data = serde_json::json!({
            "user": user,
            "index": idx,
        });

        Event::default().json_data(data)
    }))
    .chain(stream::once(async move {
        // Send final summary event
        let summary = serde_json::json!({
            "tree": tree,
            "continuation_token": continuation_token,
            "total_count": total_count,
            "complete": true
        });

        Event::default().event("summary").json_data(summary)
    }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
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
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Validate request
    if request.tuples.is_empty() {
        return Err(ApiError::InvalidRequest("No tuples provided".to_string()));
    }

    // Validate tuple format
    for tuple in &request.tuples {
        if tuple.object.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Tuple object cannot be empty".to_string(),
            ));
        }
        if tuple.relation.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Tuple relation cannot be empty".to_string(),
            ));
        }
        if tuple.user.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Tuple user cannot be empty".to_string(),
            ));
        }
        // Validate format (should contain colon)
        if !tuple.object.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid object format '{}': must be 'type:id'",
                tuple.object
            )));
        }
        if !tuple.user.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid user format '{}': must be 'type:id'",
                tuple.user
            )));
        }
    }

    // Optimistic locking: Check expected revision if provided
    if let Some(expected_rev) = &request.expected_revision {
        let current_rev = state
            .store
            .get_revision()
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

    // Write tuples to store
    let revision = state
        .store
        .write(request.tuples.clone())
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
    /// Optional expected revision for optimistic locking
    /// If provided, the write will only succeed if the current store revision matches
    pub expected_revision: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteResponse {
    pub revision: String,
    pub tuples_written: usize,
}

/// Delete tuples endpoint
async fn delete_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.write scope (delete is a write operation)
            infera_auth::middleware::require_scope(&auth_ctx, "inferadb.write")
                .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Delete request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Validate request
    if request.tuples.is_empty() {
        return Err(ApiError::InvalidRequest("No tuples provided".to_string()));
    }

    // Validate and convert tuples to TupleKeys
    let mut keys = Vec::new();
    for tuple in &request.tuples {
        if tuple.object.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Tuple object cannot be empty".to_string(),
            ));
        }
        if tuple.relation.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Tuple relation cannot be empty".to_string(),
            ));
        }
        if tuple.user.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Tuple user cannot be empty".to_string(),
            ));
        }
        // Validate format (should contain colon)
        if !tuple.object.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid object format '{}': must be 'type:id'",
                tuple.object
            )));
        }
        if !tuple.user.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid user format '{}': must be 'type:id'",
                tuple.user
            )));
        }

        // Create TupleKey for deletion
        use infera_store::TupleKey;
        keys.push(TupleKey {
            object: tuple.object.clone(),
            relation: tuple.relation.clone(),
            user: Some(tuple.user.clone()),
        });
    }

    // Optimistic locking: Check expected revision if provided
    if let Some(expected_rev) = &request.expected_revision {
        let current_rev = state
            .store
            .get_revision()
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

    // Delete tuples from store
    let mut last_revision = None;
    let mut deleted_count = 0;

    for key in keys {
        match state.store.delete(&key).await {
            Ok(revision) => {
                last_revision = Some(revision);
                deleted_count += 1;
            }
            Err(e) => {
                tracing::warn!("Failed to delete tuple {:?}: {}", key, e);
                // Continue deleting other tuples even if one fails
            }
        }
    }

    // Return the last revision from successful deletes
    let revision =
        last_revision.ok_or_else(|| ApiError::Internal("No tuples were deleted".to_string()))?;

    Ok(Json(DeleteResponse {
        revision: revision.0.to_string(),
        tuples_deleted: deleted_count,
    }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteRequest {
    pub tuples: Vec<Tuple>,
    /// Optional expected revision for optimistic locking
    /// If provided, the delete will only succeed if the current store revision matches
    pub expected_revision: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteResponse {
    pub revision: String,
    pub tuples_deleted: usize,
}

/// Simulate endpoint - run checks with ephemeral context tuples
async fn simulate_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope for simulation
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &["inferadb.check", "inferadb.simulate"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Simulate request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Validate context tuples
    if request.context_tuples.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one context tuple required".to_string(),
        ));
    }

    for tuple in &request.context_tuples {
        if tuple.object.is_empty() || tuple.relation.is_empty() || tuple.user.is_empty() {
            return Err(ApiError::InvalidRequest("Invalid tuple format".to_string()));
        }
    }

    // Create an ephemeral in-memory store with ONLY the context tuples
    // This simulates authorization decisions with temporary/what-if data
    use infera_store::MemoryBackend;
    let ephemeral_store = Arc::new(MemoryBackend::new());

    // Write context tuples to ephemeral store
    ephemeral_store
        .write(request.context_tuples.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write context tuples: {}", e)))?;

    // Create a temporary evaluator with the ephemeral store
    // Create a minimal schema for simulation (empty schema allows all relations)
    use infera_core::ipl::Schema;
    let temp_schema = Arc::new(Schema { types: Vec::new() });
    let temp_evaluator = Evaluator::new(ephemeral_store.clone(), temp_schema, None);

    // Run the check with the ephemeral data
    let check_request = CheckRequest {
        subject: request.check.subject,
        resource: request.check.resource,
        permission: request.check.permission,
        context: request.check.context,
    };

    let decision = temp_evaluator.check(check_request).await?;

    Ok(Json(SimulateResponse {
        decision,
        context_tuples_count: request.context_tuples.len(),
    }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SimulateRequest {
    pub context_tuples: Vec<Tuple>,
    pub check: SimulateCheck,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SimulateCheck {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SimulateResponse {
    pub decision: Decision,
    pub context_tuples_count: usize,
}

/// Explain endpoint - return full decision trace
async fn explain_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ExplainRequest>,
) -> Result<Json<ExplainResponse>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &["inferadb.check", "inferadb.explain"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Explain request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Run check with trace enabled
    let check_request = CheckRequest {
        subject: request.subject,
        resource: request.resource,
        permission: request.permission,
        context: request.context,
    };

    let start = std::time::Instant::now();
    let trace = state.evaluator.check_with_trace(check_request).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(Json(ExplainResponse {
        trace,
        execution_time_ms: duration_ms,
    }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExplainRequest {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExplainResponse {
    pub trace: infera_core::DecisionTrace,
    pub execution_time_ms: u64,
}

/// Start the REST API server
pub async fn serve(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn TupleStore>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
) -> anyhow::Result<()> {
    // Create health tracker
    let health_tracker = Arc::new(health::HealthTracker::new());

    // Mark service as ready to accept traffic
    health_tracker.set_ready(true);
    health_tracker.set_startup_complete(true);

    let state = AppState {
        evaluator,
        store,
        config: config.clone(),
        jwks_cache,
        health_tracker,
    };
    let app = create_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting REST API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // Setup graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn task to handle shutdown signals
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });

    // Serve with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        })
        .await?;

    Ok(())
}

/// Start the gRPC server
pub async fn serve_grpc(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn TupleStore>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
) -> anyhow::Result<()> {
    use grpc::proto::infera_service_server::InferaServiceServer;
    use tonic::transport::Server;

    // Create health tracker
    let health_tracker = Arc::new(health::HealthTracker::new());
    health_tracker.set_ready(true);
    health_tracker.set_startup_complete(true);

    let state = AppState {
        evaluator,
        store,
        config: config.clone(),
        jwks_cache: jwks_cache.clone(),
        health_tracker,
    };

    let service = grpc::InferaServiceImpl::new(state);

    // Use port + 1 for gRPC by default
    let grpc_port = config.server.port + 1;
    let addr = format!("{}:{}", config.server.host, grpc_port).parse()?;

    // Set up authentication if enabled
    if config.auth.enabled {
        if let Some(cache) = jwks_cache {
            info!(
                "Starting gRPC server on {} with authentication enabled",
                addr
            );

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
    use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
    use infera_store::MemoryBackend;
    use serde_json::json;
    use tower::ServiceExt; // for `oneshot`

    fn create_test_state() -> AppState {
        let store: Arc<dyn TupleStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new(
                    "editor".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef {
                            relation: "reader".to_string(),
                        },
                    ])),
                ),
            ],
        )]));
        let evaluator = Arc::new(Evaluator::new(Arc::clone(&store), schema, None));
        let mut config = infera_config::Config::default();
        // Disable auth and rate limiting for tests
        config.auth.enabled = false;
        config.server.rate_limiting_enabled = false;
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
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let expand_response: infera_core::ExpandResponse = serde_json::from_slice(&body).unwrap();
        assert!(matches!(
            expand_response.tree.node_type,
            infera_core::UsersetNodeType::Union
        ));
    }

    #[tokio::test]
    async fn test_delete() {
        let state = create_test_state();
        let app = create_router(state.clone());

        // First, write a tuple
        let write_request = json!({
            "tuples": [{
                "object": "doc:test",
                "relation": "reader",
                "user": "user:bob"
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

        // Verify the tuple exists
        let check_request = json!({
            "subject": "user:bob",
            "resource": "doc:test",
            "permission": "reader",
            "context": null
        });

        let response = app
            .clone()
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let check_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(check_response["decision"], "allow");

        // Now delete the tuple
        let delete_request = json!({
            "tuples": [{
                "object": "doc:test",
                "relation": "reader",
                "user": "user:bob"
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/delete")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&delete_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let delete_response: DeleteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(delete_response.tuples_deleted, 1);

        // Verify the tuple is deleted
        let check_request = json!({
            "subject": "user:bob",
            "resource": "doc:test",
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let check_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(check_response["decision"], "deny");
    }

    #[tokio::test]
    async fn test_delete_validation_empty_tuples() {
        let app = create_router(create_test_state());

        let delete_request = json!({
            "tuples": []
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/delete")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&delete_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_validation_invalid_format() {
        let app = create_router(create_test_state());

        let delete_request = json!({
            "tuples": [{
                "object": "invalid_no_colon",
                "relation": "reader",
                "user": "user:alice"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/delete")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&delete_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_batch() {
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write multiple tuples
        let write_request = json!({
            "tuples": [
                {
                    "object": "doc:batch1",
                    "relation": "reader",
                    "user": "user:charlie"
                },
                {
                    "object": "doc:batch2",
                    "relation": "reader",
                    "user": "user:charlie"
                }
            ]
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

        // Delete both tuples in batch
        let delete_request = json!({
            "tuples": [
                {
                    "object": "doc:batch1",
                    "relation": "reader",
                    "user": "user:charlie"
                },
                {
                    "object": "doc:batch2",
                    "relation": "reader",
                    "user": "user:charlie"
                }
            ]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/delete")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&delete_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let delete_response: DeleteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(delete_response.tuples_deleted, 2);
    }

    #[tokio::test]
    async fn test_rate_limiting_disabled() {
        // Verify rate limiting can be disabled in configuration
        let state = create_test_state();
        assert!(!state.config.server.rate_limiting_enabled);

        let app = create_router(state);

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

        // Should succeed with rate limiting disabled
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Note: Full rate limiting integration tests require a running HTTP server
    // with actual TCP connections to properly test IP-based rate limiting.
    // The tower-governor middleware is configured and enabled by default
    // in production (server.rate_limiting_enabled = true).
    // See docs/RATE_LIMITING.md for manual testing procedures.
}
