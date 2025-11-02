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
use infera_core::DecisionTrace;
use infera_core::Evaluator;
use infera_store::RelationshipStore;
use infera_types::{
    Decision, DeleteFilter, EvaluateRequest, ExpandRequest, ListRelationshipsRequest,
    ListResourcesRequest, ListSubjectsRequest, Relationship, RelationshipKey,
};

pub mod adapters;
pub mod formatters;
pub mod grpc;
pub mod grpc_interceptor;
pub mod handlers;
pub mod health;
pub mod routes;
pub mod validation;

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
    pub store: Arc<dyn RelationshipStore>,
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
    // All native InferaDB endpoints are versioned under /v1/
    let protected_routes = Router::new()
        .route("/v1/evaluate", post(evaluate_stream_handler))
        .route("/v1/expand", post(expand_handler))
        .route("/v1/resources/list", post(list_resources_stream_handler))
        .route(
            "/v1/relationships/list",
            post(list_relationships_stream_handler),
        )
        .route("/v1/subjects/list", post(list_subjects_stream_handler))
        .route("/v1/relationships/write", post(write_relationships_handler))
        .route(
            "/v1/relationships/delete",
            post(delete_relationships_handler),
        )
        .route(
            "/v1/relationships/:resource/:relation/:subject",
            axum::routing::get(handlers::relationships::get::get_relationship)
                .delete(handlers::relationships::delete::delete_relationship),
        )
        .route("/v1/simulate", post(simulate_handler))
        .route("/v1/watch", post(watch_handler));

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
        .route(
            "/.well-known/authzen-configuration",
            get(handlers::authzen::well_known::get_authzen_configuration),
        )
        .route(
            "/access/v1/evaluation",
            post(handlers::authzen::evaluation::post_evaluation),
        )
        .route(
            "/access/v1/evaluations",
            post(handlers::authzen::evaluation::post_evaluations),
        )
        .route(
            "/access/v1/search/resource",
            post(handlers::authzen::search::post_search_resource),
        )
        .route(
            "/access/v1/search/subject",
            post(handlers::authzen::search::post_search_subject),
        )
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

/// Request for batch authorization evaluation (streaming endpoint)
#[derive(Serialize, Deserialize)]
struct EvaluateRestRequest {
    /// Array of evaluate requests to process
    evaluations: Vec<EvaluateRequest>,
}

/// Response for a single evaluation in the batch
#[derive(Serialize, Deserialize)]
struct EvaluateRestResponse {
    /// Decision (allow or deny)
    decision: String,
    /// Index of the request this response corresponds to
    index: u32,
    /// Error message if evaluation failed
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Optional detailed evaluation trace (included when trace was set in request)
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<DecisionTrace>,
}

/// Summary event sent at the end of the stream
#[derive(Serialize, Deserialize)]
struct EvaluateSummary {
    /// Total number of evaluations processed
    total: u32,
    /// Whether the stream completed successfully
    complete: bool,
}

/// Streaming authorization evaluation endpoint using Server-Sent Events
///
/// Supports both single evaluations (array of 1) and batch evaluations (array of N).
/// Returns decisions as they're evaluated, enabling progressive rendering
/// and efficient batch processing.
async fn evaluate_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<EvaluateRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope
            infera_auth::middleware::require_scope(&auth_ctx, "inferadb.check")
                .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!(
                "Streaming check request from tenant: {}",
                auth_ctx.tenant_id
            );
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Validate request
    if request.evaluations.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one evaluation must be provided".to_string(),
        ));
    }

    let evaluations = request.evaluations;
    let total_evaluations = evaluations.len() as u32;
    let evaluator = state.evaluator.clone();

    // Create a stream that processes each evaluation and emits results
    let stream = futures::stream::iter(evaluations.into_iter().enumerate())
        .then(move |(index, evaluate_request)| {
            let evaluator = evaluator.clone();
            async move {
                // Validate individual evaluation
                if evaluate_request.subject.is_empty() {
                    return Event::default().json_data(EvaluateRestResponse {
                        decision: "deny".to_string(),
                        index: index as u32,
                        error: Some("Subject cannot be empty".to_string()),
                        trace: None,
                    });
                }
                if evaluate_request.resource.is_empty() {
                    return Event::default().json_data(EvaluateRestResponse {
                        decision: "deny".to_string(),
                        index: index as u32,
                        error: Some("Resource cannot be empty".to_string()),
                        trace: None,
                    });
                }
                if evaluate_request.permission.is_empty() {
                    return Event::default().json_data(EvaluateRestResponse {
                        decision: "deny".to_string(),
                        index: index as u32,
                        error: Some("Permission cannot be empty".to_string()),
                        trace: None,
                    });
                }

                // Check if trace is requested
                let trace = evaluate_request.trace.unwrap_or(false);

                if trace {
                    // Perform evaluation with trace
                    match evaluator.check_with_trace(evaluate_request).await {
                        Ok(trace_result) => Event::default().json_data(EvaluateRestResponse {
                            decision: match trace_result.decision {
                                Decision::Allow => "allow".to_string(),
                                Decision::Deny => "deny".to_string(),
                            },
                            index: index as u32,
                            error: None,
                            trace: Some(trace_result),
                        }),
                        Err(e) => Event::default().json_data(EvaluateRestResponse {
                            decision: "deny".to_string(),
                            index: index as u32,
                            error: Some(format!("Evaluation error: {}", e)),
                            trace: None,
                        }),
                    }
                } else {
                    // Perform regular evaluation without trace
                    match evaluator.check(evaluate_request).await {
                        Ok(decision) => Event::default().json_data(EvaluateRestResponse {
                            decision: match decision {
                                Decision::Allow => "allow".to_string(),
                                Decision::Deny => "deny".to_string(),
                            },
                            index: index as u32,
                            error: None,
                            trace: None,
                        }),
                        Err(e) => Event::default().json_data(EvaluateRestResponse {
                            decision: "deny".to_string(),
                            index: index as u32,
                            error: Some(format!("Evaluation error: {}", e)),
                            trace: None,
                        }),
                    }
                }
            }
        })
        .chain(futures::stream::once(async move {
            // Send summary event at the end
            Event::default()
                .event("summary")
                .json_data(EvaluateSummary {
                    total: total_evaluations,
                    complete: true,
                })
        }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Expand endpoint - streaming-only for progressive results
///
/// Returns users as they're discovered, enabling progressive rendering
/// for large result sets.
async fn expand_handler(
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
            "subject": user,
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

/// Write relationships endpoint
async fn write_relationships_handler(
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
    if request.relationships.is_empty() {
        return Err(ApiError::InvalidRequest(
            "No relationships provided".to_string(),
        ));
    }

    // Validate relationship format
    for relationship in &request.relationships {
        if relationship.resource.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Relationship resource cannot be empty".to_string(),
            ));
        }
        if relationship.relation.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Relationship relation cannot be empty".to_string(),
            ));
        }
        if relationship.subject.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Relationship subject cannot be empty".to_string(),
            ));
        }
        // Validate format (should contain colon)
        if !relationship.resource.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid object format '{}': must be 'type:id'",
                relationship.resource
            )));
        }
        if !relationship.subject.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid user format '{}': must be 'type:id'",
                relationship.subject
            )));
        }
        // Validate wildcard placement (wildcards only allowed in subject position as "type:*")
        if let Err(err) = relationship.validate_wildcard_placement() {
            return Err(ApiError::InvalidRequest(err));
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

    // Write relationships to store
    let revision = state
        .store
        .write(request.relationships.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write relationships: {}", e)))?;

    Ok(Json(WriteResponse {
        revision: revision.0.to_string(), // Extract the u64 value
        relationships_written: request.relationships.len(),
    }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteRequest {
    pub relationships: Vec<Relationship>,
    /// Optional expected revision for optimistic locking
    /// If provided, the write will only succeed if the current store revision matches
    pub expected_revision: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteResponse {
    pub revision: String,
    pub relationships_written: usize,
}

/// Delete relationships endpoint
async fn delete_relationships_handler(
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

    // Validate that at least one deletion method is specified
    let has_filter = request.filter.is_some();
    let has_relationships = request
        .relationships
        .as_ref()
        .is_some_and(|r| !r.is_empty());

    if !has_filter && !has_relationships {
        return Err(ApiError::InvalidRequest(
            "Must provide either filter or relationships to delete".to_string(),
        ));
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

    let mut total_deleted = 0;
    let mut last_revision = None;

    // Handle filter-based deletion if filter is provided
    if let Some(filter) = request.filter {
        // Validate filter is not empty
        if filter.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Filter must have at least one field set to avoid deleting all relationships"
                    .to_string(),
            ));
        }

        // Apply default limit of 1000 if not specified, 0 means unlimited
        let limit = match request.limit {
            Some(0) => None,    // 0 means unlimited
            Some(n) => Some(n), // Explicit limit
            None => Some(1000), // Default limit
        };

        // Perform batch deletion
        let (revision, count) = state
            .store
            .delete_by_filter(&filter, limit)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to delete by filter: {}", e)))?;

        last_revision = Some(revision);
        total_deleted += count;
    }

    // Handle exact relationship deletion if relationships are provided
    if let Some(relationships) = request.relationships {
        if !relationships.is_empty() {
            // Validate and convert relationships to RelationshipKeys
            let mut keys = Vec::new();
            for relationship in &relationships {
                if relationship.resource.is_empty() {
                    return Err(ApiError::InvalidRequest(
                        "Relationship resource cannot be empty".to_string(),
                    ));
                }
                if relationship.relation.is_empty() {
                    return Err(ApiError::InvalidRequest(
                        "Relationship relation cannot be empty".to_string(),
                    ));
                }
                if relationship.subject.is_empty() {
                    return Err(ApiError::InvalidRequest(
                        "Relationship subject cannot be empty".to_string(),
                    ));
                }
                // Validate format (should contain colon)
                if !relationship.resource.contains(':') {
                    return Err(ApiError::InvalidRequest(format!(
                        "Invalid object format '{}': must be 'type:id'",
                        relationship.resource
                    )));
                }
                if !relationship.subject.contains(':') {
                    return Err(ApiError::InvalidRequest(format!(
                        "Invalid user format '{}': must be 'type:id'",
                        relationship.subject
                    )));
                }

                keys.push(RelationshipKey {
                    resource: relationship.resource.clone(),
                    relation: relationship.relation.clone(),
                    subject: Some(relationship.subject.clone()),
                });
            }

            // Delete relationships from store
            for key in keys {
                match state.store.delete(&key).await {
                    Ok(revision) => {
                        last_revision = Some(revision);
                        total_deleted += 1;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to delete relationship {:?}: {}", key, e);
                        // Continue deleting other relationships even if one fails
                    }
                }
            }
        }
    }

    // Return the last revision from successful deletes
    let revision = last_revision
        .ok_or_else(|| ApiError::Internal("No relationships were deleted".to_string()))?;

    Ok(Json(DeleteResponse {
        revision: revision.0.to_string(),
        relationships_deleted: total_deleted,
    }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteRequest {
    /// Optional filter for bulk deletion
    /// If provided, all relationships matching the filter will be deleted
    pub filter: Option<DeleteFilter>,
    /// Optional exact relationships to delete
    /// Can be combined with filter
    pub relationships: Option<Vec<Relationship>>,
    /// Maximum number of relationships to delete (safety limit)
    /// If not specified, uses default limit (1000) for filter-based deletes
    /// Set to 0 for unlimited (use with extreme caution!)
    pub limit: Option<usize>,
    /// Optional expected revision for optimistic locking
    /// If provided, the delete will only succeed if the current store revision matches
    pub expected_revision: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteResponse {
    pub revision: String,
    pub relationships_deleted: usize,
}

/// Simulate endpoint - run checks with ephemeral context relationships
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

    // Validate context relationships
    if request.context_relationships.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one context relationship required".to_string(),
        ));
    }

    for relationship in &request.context_relationships {
        if relationship.resource.is_empty()
            || relationship.relation.is_empty()
            || relationship.subject.is_empty()
        {
            return Err(ApiError::InvalidRequest(
                "Invalid relationship format".to_string(),
            ));
        }
    }

    // Create an ephemeral in-memory store with ONLY the context relationships
    // This simulates authorization decisions with temporary/what-if data
    use infera_store::MemoryBackend;
    let ephemeral_store = Arc::new(MemoryBackend::new());

    // Write context relationships to ephemeral store
    ephemeral_store
        .write(request.context_relationships.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write context relationships: {}", e)))?;

    // Create a temporary evaluator with the ephemeral store
    // Create a minimal schema for simulation (empty schema allows all relations)
    use infera_core::ipl::Schema;
    let temp_schema = Arc::new(Schema { types: Vec::new() });
    let temp_evaluator = Evaluator::new(ephemeral_store.clone(), temp_schema, None);

    // Run the evaluation with the ephemeral data
    let evaluate_request = EvaluateRequest {
        subject: request.check.subject,
        resource: request.check.resource,
        permission: request.check.permission,
        context: request.check.context,
        trace: None,
    };

    let decision = temp_evaluator.check(evaluate_request).await?;

    Ok(Json(SimulateResponse {
        decision,
        context_relationships_count: request.context_relationships.len(),
    }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SimulateRequest {
    pub context_relationships: Vec<Relationship>,
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
    pub context_relationships_count: usize,
}

/// List resources endpoint - returns all resources accessible by a subject
#[derive(Serialize, Deserialize, Debug)]
pub struct ListResourcesRestRequest {
    /// Subject (e.g., "user:alice")
    pub subject: String,
    /// Resource type to filter by (e.g., "document")
    pub resource_type: String,
    /// Permission to check (e.g., "can_view")
    pub permission: String,
    /// Optional limit on number of resources to return
    pub limit: Option<u32>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
    /// Optional resource ID pattern filter (supports wildcards: * and ?)
    /// Examples: "doc:readme*", "user:alice_?", "folder:*/subfolder"
    pub resource_id_pattern: Option<String>,
}

/// Streaming list resources endpoint using Server-Sent Events
///
/// Returns resources as they're discovered, enabling progressive rendering
/// for large result sets.
async fn list_resources_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ListResourcesRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope (or lookup-resources scope)
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &["inferadb.check", "inferadb.list-resources"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!(
                "Streaming list resources request from tenant: {}",
                auth_ctx.tenant_id
            );
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Validate request
    if request.subject.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Subject cannot be empty".to_string(),
        ));
    }
    if request.resource_type.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Resource type cannot be empty".to_string(),
        ));
    }
    if request.permission.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Permission cannot be empty".to_string(),
        ));
    }

    // Convert to core request
    let list_request = ListResourcesRequest {
        subject: request.subject,
        resource_type: request.resource_type,
        permission: request.permission,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
        resource_id_pattern: request.resource_id_pattern,
    };

    // Execute the lookup operation
    let response = state.evaluator.list_resources(list_request).await?;

    // Create a stream that sends each resource as a separate SSE event
    let resources = response.resources;
    let cursor = response.cursor;
    let total_count = response.total_count;

    let stream = stream::iter(resources.into_iter().enumerate().map(|(idx, resource)| {
        let data = serde_json::json!({
            "resource": resource,
            "index": idx,
        });

        Event::default().json_data(data)
    }))
    .chain(stream::once(async move {
        // Send final summary event
        let summary = serde_json::json!({
            "cursor": cursor,
            "total_count": total_count,
            "complete": true
        });

        Event::default().event("summary").json_data(summary)
    }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// List relationships endpoint - returns relationships matching optional filters

#[derive(Serialize, Deserialize, Debug)]
pub struct ListRelationshipsRestRequest {
    /// Optional filter by resource (e.g., "doc:readme")
    pub resource: Option<String>,
    /// Optional filter by relation (e.g., "viewer")
    pub relation: Option<String>,
    /// Optional filter by subject (e.g., "user:alice")
    pub subject: Option<String>,
    /// Optional limit on number of relationships to return (default: 100, max: 1000)
    pub limit: Option<u32>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
}

/// Streaming list relationships endpoint using Server-Sent Events
///
/// Returns relationships as they're discovered, enabling progressive rendering
/// for large result sets.
async fn list_relationships_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ListRelationshipsRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope (or list-relationships scope)
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &["inferadb.check", "inferadb.list-relationships"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!(
                "Streaming list relationships request from tenant: {}",
                auth_ctx.tenant_id
            );
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Convert to core request (all filters are optional)
    let list_request = ListRelationshipsRequest {
        resource: request.resource,
        relation: request.relation,
        subject: request.subject,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
    };

    // Execute the list operation
    let response = state.evaluator.list_relationships(list_request).await?;

    // Response already uses Relationship type with resource/subject
    let relationships = response.relationships;
    let cursor = response.cursor;
    let total_count = response.total_count;

    let stream = stream::iter(
        relationships
            .into_iter()
            .enumerate()
            .map(|(idx, relationship)| {
                let data = serde_json::json!({
                    "relationship": relationship,
                    "index": idx,
                });

                Event::default().json_data(data)
            }),
    )
    .chain(stream::once(async move {
        // Send final summary event
        let summary = serde_json::json!({
            "cursor": cursor,
            "total_count": total_count,
            "complete": true
        });

        Event::default().event("summary").json_data(summary)
    }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Request format for the list subjects REST endpoint
#[derive(Debug, Deserialize, Serialize)]
pub struct ListSubjectsRestRequest {
    /// Resource (e.g., "document:readme")
    pub resource: String,
    /// Relation to check (e.g., "viewer")
    pub relation: String,
    /// Optional filter by subject type (e.g., "user", "group")
    pub subject_type: Option<String>,
    /// Optional limit on number of subjects to return (default: 100, max: 1000)
    pub limit: Option<u32>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
}

/// Streaming list subjects endpoint using Server-Sent Events
///
/// Returns subjects as they're discovered, enabling progressive rendering
/// for large result sets.
async fn list_subjects_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ListSubjectsRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope (or list-subjects scope)
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &["inferadb.check", "inferadb.list-subjects"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!(
                "Streaming list subjects request from tenant: {}",
                auth_ctx.tenant_id
            );
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Convert to core request
    let list_request = ListSubjectsRequest {
        resource: request.resource,
        relation: request.relation,
        subject_type: request.subject_type,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
    };

    // Execute the list operation
    let response = state.evaluator.list_subjects(list_request).await?;

    let subjects = response.subjects;
    let cursor = response.cursor;
    let total_count = response.total_count;

    let stream = stream::iter(subjects.into_iter().enumerate().map(|(idx, subject)| {
        let data = serde_json::json!({
            "subject": subject,
            "index": idx,
        });

        Event::default().json_data(data)
    }))
    .chain(stream::once(async move {
        // Send final summary event
        let summary = serde_json::json!({
            "cursor": cursor,
            "total_count": total_count,
            "complete": true
        });

        Event::default().event("summary").json_data(summary)
    }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// REST request for Watch endpoint
#[derive(Debug, Deserialize, Serialize)]
pub struct WatchRestRequest {
    /// Optional filter by resource types (e.g., ["document", "folder"])
    /// If empty, watches all relationship changes
    #[serde(default)]
    pub resource_types: Vec<String>,
    /// Optional start cursor/revision to resume from
    /// If None, starts from current point in time
    pub cursor: Option<String>,
}

/// Watch endpoint using Server-Sent Events
///
/// Returns a continuous stream of relationship changes as they occur.
/// The stream remains open indefinitely until the client disconnects.
async fn watch_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<WatchRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.watch scope
            infera_auth::middleware::require_any_scope(&auth_ctx, &["inferadb.watch"])
                .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Watch request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized(
                "Authentication required".to_string(),
            ));
        }
    }

    // Parse cursor (base64 decode to revision)
    let start_revision = if let Some(cursor) = &request.cursor {
        use base64::{engine::general_purpose, Engine as _};
        let decoded = general_purpose::STANDARD
            .decode(cursor)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid cursor: {}", e)))?;
        let revision_str = String::from_utf8(decoded)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid cursor encoding: {}", e)))?;
        let revision_u64 = revision_str
            .parse::<u64>()
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid cursor format: {}", e)))?;
        infera_types::Revision(revision_u64)
    } else {
        // Start from next revision
        let current =
            state.store.get_revision().await.map_err(|e| {
                ApiError::Internal(format!("Failed to get current revision: {}", e))
            })?;
        current.next()
    };

    let resource_types = request.resource_types;
    let store = Arc::clone(&state.store);

    // Create a continuous polling stream
    let stream = async_stream::stream! {
        let mut last_revision = start_revision;

        loop {
            // Read changes from the change log
            match store.read_changes(last_revision, &resource_types, Some(100)).await {
                Ok(events) => {
                    for event in &events {
                        // Format timestamp as ISO 8601
                        let timestamp = {
                            let secs = event.timestamp_nanos / 1_000_000_000;
                            let nanos = (event.timestamp_nanos % 1_000_000_000) as u32;
                            chrono::DateTime::from_timestamp(secs, nanos)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
                        };

                        let operation = match event.operation {
                            infera_types::ChangeOperation::Create => "create",
                            infera_types::ChangeOperation::Delete => "delete",
                        };

                        let data = serde_json::json!({
                            "operation": operation,
                            "relationship": {
                                "resource": event.relationship.resource,
                                "relation": event.relationship.relation,
                                "subject": event.relationship.subject,
                            },
                            "revision": event.revision.0.to_string(),
                            "timestamp": timestamp,
                        });

                        last_revision = event.revision.next();

                        let result = Event::default()
                            .event("change")
                            .json_data(data);

                        yield result;
                    }

                    // If no events, wait a bit before polling again
                    if events.is_empty() {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
                Err(e) => {
                    let error_data = serde_json::json!({
                        "error": format!("Failed to read changes: {}", e)
                    });

                    let result = Event::default()
                        .event("error")
                        .json_data(error_data);

                    yield result;
                    break;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Start the REST API server
pub async fn serve(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn RelationshipStore>,
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
    store: Arc<dyn RelationshipStore>,
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

    // Set up reflection service
    let file_descriptor_set = tonic::include_file_descriptor_set!("infera_descriptor");
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(file_descriptor_set)
        .build_v1()?;

    info!("gRPC reflection enabled");

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

            // Add service with interceptor and reflection
            Server::builder()
                .add_service(InferaServiceServer::with_interceptor(service, interceptor))
                .add_service(reflection_service)
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
            .add_service(reflection_service)
            .serve(addr)
            .await?;
    }

    Ok(())
}

/// Start both REST and gRPC servers concurrently
pub async fn serve_both(
    evaluator: Arc<Evaluator>,
    store: Arc<dyn RelationshipStore>,
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
    use infera_types::{UsersetNodeType, UsersetTree};
    use serde_json::json;
    use tower::ServiceExt; // for `oneshot`

    fn create_test_state() -> AppState {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());
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

        let health_tracker = Arc::new(health::HealthTracker::new());
        health_tracker.set_ready(true);
        health_tracker.set_startup_complete(true);

        AppState {
            evaluator,
            store,
            config,
            jwks_cache: None,
            health_tracker,
        }
    }

    /// Helper function to parse SSE response and extract evaluation results
    async fn parse_sse_evaluate_response(body: &[u8]) -> Vec<EvaluateRestResponse> {
        let body_str = std::str::from_utf8(body).expect("Invalid UTF-8 in SSE response");
        let mut results = Vec::new();

        // Parse SSE format: "data: {...}\n\n"
        for line in body_str.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                // Try to parse as EvaluateRestResponse (skip summary events)
                if let Ok(response) = serde_json::from_str::<EvaluateRestResponse>(data) {
                    results.push(response);
                }
            }
        }

        results
    }

    /// Helper to parse SSE expand response and extract users and summary
    #[derive(serde::Deserialize, Debug)]
    struct ExpandSseUser {
        subject: String,
        #[allow(dead_code)]
        index: usize,
    }

    #[derive(serde::Deserialize, Debug)]
    struct ExpandSseSummary {
        tree: UsersetTree,
        #[allow(dead_code)]
        total_count: Option<u64>,
        complete: bool,
    }

    async fn parse_sse_expand_response(body: &[u8]) -> (Vec<String>, Option<ExpandSseSummary>) {
        let body_str = std::str::from_utf8(body).expect("Invalid UTF-8 in SSE response");
        let mut users = Vec::new();
        let mut summary = None;

        let mut current_event = "";
        for line in body_str.lines() {
            if let Some(event_type) = line.strip_prefix("event: ") {
                current_event = event_type;
            } else if let Some(data) = line.strip_prefix("data: ") {
                if current_event == "summary" {
                    summary = serde_json::from_str::<ExpandSseSummary>(data).ok();
                } else {
                    // Regular user event
                    if let Ok(user_data) = serde_json::from_str::<ExpandSseUser>(data) {
                        users.push(user_data.subject);
                    }
                }
            }
        }

        (users, summary)
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

        // New batch format with array of checks
        let request_body = json!({
            "evaluations": [{
                "subject": "user:alice",
                "resource": "doc:readme",
                "permission": "reader",
                "context": null
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
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

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "deny");
        assert_eq!(results[0].index, 0);
        assert!(results[0].error.is_none());
    }

    #[tokio::test]
    async fn test_write_and_check() {
        let state = create_test_state();
        let app = create_router(state.clone());

        // First, write a relationship
        let write_request = json!({
            "relationships": [{
                "resource": "doc:readme",
                "relation": "reader",
                "subject": "user:alice"
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
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
        assert_eq!(write_response.relationships_written, 1);

        // Now check the permission
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:alice",
                "resource": "doc:readme",
                "permission": "reader",
                "context": null
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");
        assert_eq!(results[0].index, 0);
        assert!(results[0].error.is_none());
    }

    #[tokio::test]
    async fn test_write_validation_empty_relationships() {
        let app = create_router(create_test_state());

        let write_request = json!({
            "relationships": []
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
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
            "relationships": [{
                "resource": "invalid",  // Missing colon
                "relation": "reader",
                "subject": "user:alice"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
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
                    .uri("/v1/expand")
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

        // Parse SSE response
        let (_users, summary) = parse_sse_expand_response(&body).await;
        assert!(summary.is_some());

        let summary = summary.unwrap();
        assert!(summary.complete);
        assert!(matches!(summary.tree.node_type, UsersetNodeType::Union));
    }

    #[tokio::test]
    async fn test_delete() {
        let state = create_test_state();
        let app = create_router(state.clone());

        // First, write a relationship
        let write_request = json!({
            "relationships": [{
                "resource": "doc:test",
                "relation": "reader",
                "subject": "user:bob"
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the relationship exists
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:bob",
                "resource": "doc:test",
                "permission": "reader",
                "context": null
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");

        // Now delete the relationship
        let delete_request = json!({
            "relationships": [{
                "resource": "doc:test",
                "relation": "reader",
                "subject": "user:bob"
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
        assert_eq!(delete_response.relationships_deleted, 1);

        // Verify the relationship is deleted
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:bob",
                "resource": "doc:test",
                "permission": "reader",
                "context": null
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "deny");
    }

    #[tokio::test]
    async fn test_delete_validation_empty_relationships() {
        let app = create_router(create_test_state());

        // Empty request with no filter and no relationships should fail
        let delete_request = json!({});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
            "relationships": [{
                "resource": "invalid_no_colon",
                "relation": "reader",
                "subject": "user:alice"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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

        // Write multiple relationships
        let write_request = json!({
            "relationships": [
                {
                    "resource": "doc:batch1",
                    "relation": "reader",
                    "subject": "user:charlie"
                },
                {
                    "resource": "doc:batch2",
                    "relation": "reader",
                    "subject": "user:charlie"
                }
            ]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Delete both relationships in batch
        let delete_request = json!({
            "relationships": [
                {
                    "resource": "doc:batch1",
                    "relation": "reader",
                    "subject": "user:charlie"
                },
                {
                    "resource": "doc:batch2",
                    "relation": "reader",
                    "subject": "user:charlie"
                }
            ]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
        assert_eq!(delete_response.relationships_deleted, 2);
    }

    #[tokio::test]
    async fn test_rate_limiting_disabled() {
        // Verify rate limiting can be disabled in configuration
        let state = create_test_state();
        assert!(!state.config.server.rate_limiting_enabled);

        let app = create_router(state);

        let request_body = json!({
            "evaluations": [{
                "subject": "user:alice",
                "resource": "doc:readme",
                "permission": "reader",
                "context": null
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
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

    #[tokio::test]
    async fn test_lookup_resources_validation() {
        let app = create_router(create_test_state());

        // Test empty subject
        let list_request = json!({
            "subject": "",
            "resource_type": "doc",
            "permission": "reader"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/resources/list")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&list_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test empty resource_type
        let list_request = json!({
            "subject": "user:alice",
            "resource_type": "",
            "permission": "reader"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/resources/list")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&list_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test empty permission
        let list_request = json!({
            "subject": "user:alice",
            "resource_type": "doc",
            "permission": ""
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/resources/list")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&list_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_by_filter_subject() {
        // Test user offboarding scenario: delete all relationships for a subject
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write relationships for alice across multiple resources
        let write_request = json!({
            "relationships": [
                {
                    "resource": "doc:1",
                    "relation": "reader",
                    "subject": "user:alice"
                },
                {
                    "resource": "doc:2",
                    "relation": "editor",
                    "subject": "user:alice"
                },
                {
                    "resource": "doc:3",
                    "relation": "reader",
                    "subject": "user:bob"
                }
            ]
        });

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Delete all relationships for alice
        let delete_request = json!({
            "filter": {
                "subject": "user:alice"
            }
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
        assert_eq!(delete_response.relationships_deleted, 2);

        // Verify alice has no access anymore
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:alice",
                "resource": "doc:1",
                "permission": "reader"
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "deny");

        // Verify bob still has access
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:bob",
                "resource": "doc:3",
                "permission": "reader"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");
    }

    #[tokio::test]
    async fn test_delete_by_filter_resource() {
        // Test resource cleanup scenario: delete all relationships for a resource
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write relationships with multiple subjects for the same resource
        let write_request = json!({
            "relationships": [
                {
                    "resource": "doc:cleanup",
                    "relation": "reader",
                    "subject": "user:alice"
                },
                {
                    "resource": "doc:cleanup",
                    "relation": "editor",
                    "subject": "user:bob"
                },
                {
                    "resource": "doc:keep",
                    "relation": "reader",
                    "subject": "user:alice"
                }
            ]
        });

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Delete all relationships for doc:cleanup
        let delete_request = json!({
            "filter": {
                "resource": "doc:cleanup"
            }
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
        assert_eq!(delete_response.relationships_deleted, 2);

        // Verify doc:cleanup relationships are deleted
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:alice",
                "resource": "doc:cleanup",
                "permission": "reader"
            }]
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "deny");

        // Verify doc:keep relationships still exist
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:alice",
                "resource": "doc:keep",
                "permission": "reader"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");
    }

    #[tokio::test]
    async fn test_delete_by_filter_with_limit() {
        // Test deletion with explicit limit
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write multiple relationships for the same subject
        let write_request = json!({
            "relationships": [
                {
                    "resource": "doc:1",
                    "relation": "reader",
                    "subject": "user:charlie"
                },
                {
                    "resource": "doc:2",
                    "relation": "reader",
                    "subject": "user:charlie"
                },
                {
                    "resource": "doc:3",
                    "relation": "reader",
                    "subject": "user:charlie"
                }
            ]
        });

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Delete with limit of 2
        let delete_request = json!({
            "filter": {
                "subject": "user:charlie"
            },
            "limit": 2
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
        // Should only delete 2 relationships due to limit
        assert_eq!(delete_response.relationships_deleted, 2);
    }

    #[tokio::test]
    async fn test_delete_by_filter_combined_fields() {
        // Test deletion with multiple filter fields
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write relationships with various combinations
        let write_request = json!({
            "relationships": [
                {
                    "resource": "doc:1",
                    "relation": "reader",
                    "subject": "user:dave"
                },
                {
                    "resource": "doc:1",
                    "relation": "editor",
                    "subject": "user:dave"
                },
                {
                    "resource": "doc:2",
                    "relation": "reader",
                    "subject": "user:dave"
                }
            ]
        });

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Delete only reader relationships for doc:1
        let delete_request = json!({
            "filter": {
                "resource": "doc:1",
                "relation": "reader"
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
        // Should only delete the one matching relationship
        assert_eq!(delete_response.relationships_deleted, 1);
    }

    #[tokio::test]
    async fn test_delete_filter_empty_validation() {
        // Test that empty filter is rejected
        let app = create_router(create_test_state());

        let delete_request = json!({
            "filter": {}
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&delete_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should fail with bad request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_batch_check() {
        // Test new batch check functionality - multiple checks in single request
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write some relationships
        let write_request = json!({
            "relationships": [
                {
                    "resource": "doc:1",
                    "relation": "reader",
                    "subject": "user:alice"
                },
                {
                    "resource": "doc:2",
                    "relation": "editor",
                    "subject": "user:bob"
                }
            ]
        });

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Batch check: test multiple permissions in single request
        let batch_request = json!({
            "evaluations": [
                {
                    "subject": "user:alice",
                    "resource": "doc:1",
                    "permission": "reader"
                },
                {
                    "subject": "user:alice",
                    "resource": "doc:2",
                    "permission": "reader"
                },
                {
                    "subject": "user:bob",
                    "resource": "doc:2",
                    "permission": "editor"
                },
                {
                    "subject": "user:bob",
                    "resource": "doc:1",
                    "permission": "editor"
                }
            ]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&batch_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE batch response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 4); // Should get 4 results back

        // Verify results by index
        assert_eq!(results[0].index, 0);
        assert_eq!(results[0].decision, "allow"); // alice can read doc:1
        assert!(results[0].error.is_none());

        assert_eq!(results[1].index, 1);
        assert_eq!(results[1].decision, "deny"); // alice can't read doc:2
        assert!(results[1].error.is_none());

        assert_eq!(results[2].index, 2);
        assert_eq!(results[2].decision, "allow"); // bob can edit doc:2
        assert!(results[2].error.is_none());

        assert_eq!(results[3].index, 3);
        assert_eq!(results[3].decision, "deny"); // bob can't edit doc:1
        assert!(results[3].error.is_none());
    }

    #[tokio::test]
    async fn test_check_with_trace() {
        // Test unified Check API with trace flag
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write a relationship
        let write_request = json!({
            "relationships": [{
                "resource": "doc:traced",
                "relation": "reader",
                "subject": "user:alice"
            }]
        });

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Check with trace enabled
        let evaluate_request = json!({
            "evaluations": [{
                "subject": "user:alice",
                "resource": "doc:traced",
                "permission": "reader",
                "trace": true
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&evaluate_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");
        assert_eq!(results[0].index, 0);
        assert!(results[0].error.is_none());

        // Verify trace is included
        assert!(results[0].trace.is_some());
        let trace = results[0].trace.as_ref().unwrap();
        assert!(trace.duration.as_micros() > 0);
        // root is an EvaluationNode, not an Option
    }

    #[tokio::test]
    async fn test_delete_combined_filter_and_exact() {
        // Test deletion with both filter and exact relationships
        let state = create_test_state();
        let app = create_router(state.clone());

        // Write multiple relationships
        let write_request = json!({
            "relationships": [
                {
                    "resource": "doc:1",
                    "relation": "reader",
                    "subject": "user:eve"
                },
                {
                    "resource": "doc:2",
                    "relation": "reader",
                    "subject": "user:eve"
                },
                {
                    "resource": "doc:3",
                    "relation": "reader",
                    "subject": "user:frank"
                }
            ]
        });

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&write_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Delete using both filter (for eve) and exact relationship (for frank)
        let delete_request = json!({
            "filter": {
                "subject": "user:eve"
            },
            "relationships": [{
                "resource": "doc:3",
                "relation": "reader",
                "subject": "user:frank"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/relationships/delete")
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
        // Should delete 2 for eve + 1 for frank = 3 total
        assert_eq!(delete_response.relationships_deleted, 3);
    }
}
