//! # Infera API - REST and gRPC API Layer
//!
//! Exposes REST and gRPC endpoints for authorization checks (AuthZEN-compatible).

use std::sync::Arc;

use axum::{
    Json, Router,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use infera_auth::jwks_cache::JwksCache;
use infera_config::Config;
use serde::Serialize;
use thiserror::Error;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{compression::CompressionLayer, cors::CorsLayer};
use tracing::info;
use uuid::Uuid;

pub mod adapters;
pub mod content_negotiation;
pub mod formatters;
pub mod grpc;
pub mod grpc_interceptor;
pub mod handlers;
pub mod health;
pub mod routes;
pub mod services;
pub mod validation;
pub mod vault_validation;

// Import handlers
#[cfg(test)]
use handlers::evaluate::stream::EvaluateRestResponse;
use handlers::{
    evaluate::stream::evaluate_stream_handler,
    expand::stream::expand_handler,
    relationships::{
        delete::delete_relationships_handler, list::list_relationships_stream_handler,
        write::write_relationships_handler,
    },
    resources::list::list_resources_stream_handler,
    simulate::evaluate::simulate_handler,
    subjects::list::list_subjects_stream_handler,
    watch::stream::watch_handler,
};

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

impl From<infera_auth::AuthError> for ApiError {
    fn from(err: infera_auth::AuthError) -> Self {
        ApiError::Internal(format!("Authentication system error: {}", err))
    }
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

            // Rate limit error with Retry-After header
            ApiError::RateLimitExceeded => {
                let mut headers = HeaderMap::new();
                headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                headers.insert("x-ratelimit-limit", HeaderValue::from_static("1000"));
                headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
                (StatusCode::TOO_MANY_REQUESTS, self.to_string(), Some(headers))
            },

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
    pub store: Arc<dyn infera_store::InferaStore>,
    pub config: Arc<Config>,
    pub jwks_cache: Option<Arc<JwksCache>>,
    pub health_tracker: Arc<health::HealthTracker>,
    /// Default vault ID used when authentication is disabled
    pub default_vault: Uuid,
    /// Default account ID used when authentication is disabled
    pub default_account: Uuid,

    // Shared cache for authorization decisions and expansions
    pub auth_cache: Arc<infera_cache::AuthCache>,

    // Service layer (protocol-agnostic business logic)
    pub evaluation_service: Arc<services::EvaluationService>,
    pub resource_service: Arc<services::ResourceService>,
    pub subject_service: Arc<services::SubjectService>,
    pub relationship_service: Arc<services::RelationshipService>,
    pub expansion_service: Arc<services::ExpansionService>,
    pub watch_service: Arc<services::WatchService>,
}

impl AppState {
    /// Creates a new AppState with services
    ///
    /// This is a convenience constructor that creates all services from the provided components.
    pub fn new(
        store: Arc<dyn infera_store::InferaStore>,
        schema: Arc<infera_core::ipl::Schema>,
        wasm_host: Option<Arc<infera_wasm::WasmHost>>,
        config: Arc<Config>,
        jwks_cache: Option<Arc<JwksCache>>,
        default_vault: Uuid,
        default_account: Uuid,
    ) -> Self {
        let health_tracker = Arc::new(health::HealthTracker::new());

        // Create shared cache
        let auth_cache = if config.cache.enabled {
            Arc::new(infera_cache::AuthCache::new(
                config.cache.max_capacity,
                std::time::Duration::from_secs(config.cache.ttl_seconds),
            ))
        } else {
            // Create a minimal cache that won't be used
            Arc::new(infera_cache::AuthCache::new(1, std::time::Duration::from_secs(1)))
        };

        // Determine which cache to pass to services
        let service_cache = if config.cache.enabled { Some(Arc::clone(&auth_cache)) } else { None };

        // Create services with shared cache
        let evaluation_service = Arc::new(services::EvaluationService::new(
            Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>,
            Arc::clone(&schema),
            wasm_host.clone(),
            service_cache.clone(),
        ));

        let resource_service = Arc::new(services::ResourceService::new(
            Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>,
            Arc::clone(&schema),
            wasm_host.clone(),
            service_cache.clone(),
        ));

        let subject_service = Arc::new(services::SubjectService::new(
            Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>,
            Arc::clone(&schema),
            wasm_host.clone(),
            service_cache.clone(),
        ));

        let relationship_service = Arc::new(services::RelationshipService::new(
            Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>,
            Arc::clone(&schema),
            wasm_host.clone(),
            service_cache.clone(),
        ));

        let expansion_service = Arc::new(services::ExpansionService::new(
            Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>,
            Arc::clone(&schema),
            wasm_host.clone(),
            service_cache,
        ));

        let watch_service = Arc::new(services::WatchService::new(
            Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>
        ));

        Self {
            store,
            config,
            jwks_cache,
            health_tracker,
            default_vault,
            default_account,
            auth_cache,
            evaluation_service,
            resource_service,
            subject_service,
            relationship_service,
            expansion_service,
            watch_service,
        }
    }
}

/// Create the API router
pub fn create_router(state: AppState) -> Result<Router> {
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

    let governor_layer = GovernorLayer::new(governor_conf);

    // Protected routes that require authentication
    // All native InferaDB endpoints are versioned under /v1/
    let protected_routes = Router::new()
        .route("/v1/evaluate", post(evaluate_stream_handler))
        .route("/v1/expand", post(expand_handler))
        .route("/v1/resources/list", post(list_resources_stream_handler))
        .route("/v1/relationships/list", post(list_relationships_stream_handler))
        .route("/v1/subjects/list", post(list_subjects_stream_handler))
        .route("/v1/relationships/write", post(write_relationships_handler))
        .route("/v1/relationships/delete", post(delete_relationships_handler))
        .route(
            "/v1/relationships/{resource}/{relation}/{subject}",
            axum::routing::get(handlers::relationships::get::get_relationship)
                .delete(handlers::relationships::delete::delete_relationship),
        )
        .route("/v1/simulate", post(simulate_handler))
        .route("/v1/watch", post(watch_handler))
        // Account management routes
        .route(
            "/v1/accounts",
            post(handlers::accounts::create::create_account)
                .get(handlers::accounts::list::list_accounts),
        )
        .route(
            "/v1/accounts/{id}",
            axum::routing::get(handlers::accounts::get::get_account)
                .patch(handlers::accounts::update::update_account)
                .delete(handlers::accounts::delete::delete_account),
        )
        // Vault management routes
        .route(
            "/v1/accounts/{account_id}/vaults",
            post(handlers::vaults::create::create_vault).get(handlers::vaults::list::list_vaults),
        )
        .route(
            "/v1/vaults/{id}",
            axum::routing::get(handlers::vaults::get::get_vault)
                .patch(handlers::vaults::update::update_vault)
                .delete(handlers::vaults::delete::delete_vault),
        )
        // AuthZEN-compliant endpoints (require authentication for vault isolation)
        .route("/access/v1/evaluation", post(handlers::authzen::evaluation::post_evaluation))
        .route("/access/v1/evaluations", post(handlers::authzen::evaluation::post_evaluations))
        .route("/access/v1/search/resource", post(handlers::authzen::search::post_search_resource))
        .route("/access/v1/search/subject", post(handlers::authzen::search::post_search_subject));

    // Create VaultVerifier instance based on configuration
    let vault_verifier: Arc<dyn infera_auth::VaultVerifier> = if state.config.auth.enabled
        && !state.config.auth.management_api_url.is_empty()
    {
        // Use management API for vault verification
        let management_client = infera_auth::ManagementClient::new(
            state.config.auth.management_api_url.clone(),
            state.config.auth.management_api_timeout_ms,
        )
        .map_err(|e| ApiError::Internal(format!("Failed to create management client: {}", e)))?;

        info!(
            "Vault verification ENABLED - using management API at {}",
            state.config.auth.management_api_url
        );
        Arc::new(infera_auth::ManagementApiVaultVerifier::new(
            Arc::new(management_client),
            std::time::Duration::from_secs(300), // 5 min vault cache TTL
            std::time::Duration::from_secs(600), // 10 min org cache TTL
        ))
    } else {
        // Use no-op verifier when auth is disabled or management API not configured
        info!("Vault verification DISABLED - using no-op verifier");
        Arc::new(infera_auth::NoOpVaultVerifier)
    };

    // Apply authentication middleware (either with JWT validation or default context)
    let protected_routes = if state.config.auth.enabled {
        if let Some(jwks_cache) = &state.jwks_cache {
            info!("Authentication ENABLED - applying auth middleware to protected routes");
            let jwks_cache = Arc::clone(jwks_cache);
            let auth_enabled = state.config.auth.enabled;

            // Use default vault and account from AppState
            let default_vault = state.default_vault;
            let default_account = state.default_account;

            // Apply auth middleware first, then vault validation middleware
            // Note: Layers are applied in reverse order, so vault validation runs after auth
            let vault_verifier_clone = Arc::clone(&vault_verifier);
            protected_routes
                .layer(axum::middleware::from_fn(move |req, next| {
                    let verifier = Arc::clone(&vault_verifier_clone);
                    async move {
                        infera_auth::enhanced_vault_validation_middleware(verifier).await(req, next)
                            .await
                    }
                }))
                .layer(axum::middleware::from_fn(move |req, next| {
                    let jwks_cache = Arc::clone(&jwks_cache);
                    infera_auth::middleware::optional_auth_middleware(
                        auth_enabled,
                        default_vault,
                        default_account,
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
        // Auth disabled - inject default AuthContext
        tracing::warn!("Authentication DISABLED - using default vault for all requests");
        let auth_enabled = false;

        // Use default vault and account from AppState
        let default_vault = state.default_vault;
        let default_account = state.default_account;

        // Create a dummy JWKS cache (not used when auth is disabled)
        let dummy_jwks_cache = Arc::new(infera_auth::jwks_cache::JwksCache::new(
            "https://unused.example.com".to_string(),
            Arc::new(moka::future::Cache::new(1)),
            std::time::Duration::from_secs(300),
        )?);

        // No vault validation when auth is disabled
        protected_routes.layer(axum::middleware::from_fn(move |req, next| {
            let jwks_cache = Arc::clone(&dummy_jwks_cache);
            infera_auth::middleware::optional_auth_middleware(
                auth_enabled,
                default_vault,
                default_account,
                jwks_cache,
                req,
                next,
            )
        }))
    };

    // Combine health endpoints and public discovery with protected routes
    // Note: AuthZEN /access/v1/* endpoints are now in protected_routes for vault isolation
    let router = Router::new()
        .route("/health", get(health::health_check_handler))
        .route("/health/live", get(health::liveness_handler))
        .route("/health/ready", get(health::readiness_handler))
        .route("/health/startup", get(health::startup_handler))
        .route("/health/auth", get(health::auth_health_check_handler))
        // AuthZEN configuration endpoint (public for service discovery)
        .route(
            "/.well-known/authzen-configuration",
            get(handlers::authzen::well_known::get_authzen_configuration),
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
    let router = if state.config.server.rate_limiting_enabled {
        info!("Rate limiting ENABLED - applying governor layer");
        router.layer(governor_layer)
    } else {
        info!("Rate limiting DISABLED - skipping governor layer");
        router
    };

    Ok(router)
}

// Health check handlers moved to health.rs module

/// Graceful shutdown signal handler
///
/// Waits for SIGTERM (Kubernetes) or SIGINT (Ctrl+C) and initiates graceful shutdown.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
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

/// Start the REST API server
pub async fn serve(
    store: Arc<dyn infera_store::InferaStore>,
    schema: Arc<infera_core::ipl::Schema>,
    wasm_host: Option<Arc<infera_wasm::WasmHost>>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
    default_vault: Uuid,
    default_account: Uuid,
) -> anyhow::Result<()> {
    // Create AppState with services
    let state = AppState::new(
        store,
        schema,
        wasm_host,
        config.clone(),
        jwks_cache,
        default_vault,
        default_account,
    );

    // Mark service as ready to accept traffic
    state.health_tracker.set_ready(true);
    state.health_tracker.set_startup_complete(true);

    let app = create_router(state)?;

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
    store: Arc<dyn infera_store::InferaStore>,
    schema: Arc<infera_core::ipl::Schema>,
    wasm_host: Option<Arc<infera_wasm::WasmHost>>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
    default_vault: Uuid,
    default_account: Uuid,
) -> anyhow::Result<()> {
    use grpc::proto::infera_service_server::InferaServiceServer;
    use tonic::transport::Server;

    // Create AppState with services
    let state = AppState::new(
        store,
        schema,
        wasm_host,
        config.clone(),
        jwks_cache,
        default_vault,
        default_account,
    );

    // Mark service as ready to accept traffic
    state.health_tracker.set_ready(true);
    state.health_tracker.set_startup_complete(true);

    let service = grpc::InferaServiceImpl::new(state.clone());

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
        if let Some(cache) = state.jwks_cache.as_ref() {
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
                Arc::clone(cache),
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
            return Err(anyhow::anyhow!("Authentication enabled but JWKS cache not initialized"));
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
    store: Arc<dyn infera_store::InferaStore>,
    schema: Arc<infera_core::ipl::Schema>,
    wasm_host: Option<Arc<infera_wasm::WasmHost>>,
    config: Arc<Config>,
    jwks_cache: Option<Arc<JwksCache>>,
    default_vault: Uuid,
    default_account: Uuid,
) -> anyhow::Result<()> {
    let rest_store = Arc::clone(&store);
    let rest_schema = Arc::clone(&schema);
    let rest_wasm_host = wasm_host.clone();
    let rest_config = Arc::clone(&config);
    let rest_jwks_cache = jwks_cache.as_ref().map(Arc::clone);

    let grpc_store = Arc::clone(&store);
    let grpc_schema = Arc::clone(&schema);
    let grpc_wasm_host = wasm_host.clone();
    let grpc_config = Arc::clone(&config);
    let grpc_jwks_cache = jwks_cache.as_ref().map(Arc::clone);

    tokio::try_join!(
        serve(
            rest_store,
            rest_schema,
            rest_wasm_host,
            rest_config,
            rest_jwks_cache,
            default_vault,
            default_account
        ),
        serve_grpc(
            grpc_store,
            grpc_schema,
            grpc_wasm_host,
            grpc_config,
            grpc_jwks_cache,
            default_vault,
            default_account
        )
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use handlers::relationships::{delete::DeleteResponse, write::WriteResponse};
    use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
    use infera_store::MemoryBackend;
    use infera_types::{UsersetNodeType, UsersetTree};
    use serde_json::json;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*; // for `oneshot`

    fn create_test_state() -> AppState {
        let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new(
                    "editor".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "reader".to_string() },
                    ])),
                ),
            ],
        )]));
        // Use a test vault ID
        let test_vault = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let test_account = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();

        let mut config = infera_config::Config::default();
        // Disable auth and rate limiting for tests
        config.auth.enabled = false;
        config.server.rate_limiting_enabled = false;
        let config = Arc::new(config);

        // Use AppState::new() to create state with all services
        let state = AppState::new(
            store,
            schema,
            None, // No WASM host for tests
            config,
            None, // No JWKS cache for tests
            test_vault,
            test_account,
        );

        state.health_tracker.set_ready(true);
        state.health_tracker.set_startup_complete(true);

        state
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
        let app = create_router(create_test_state()).unwrap();

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_check_deny() {
        let app = create_router(create_test_state()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

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
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");
        assert_eq!(results[0].index, 0);
        assert!(results[0].error.is_none());
    }

    #[tokio::test]
    async fn test_write_validation_empty_relationships() {
        let app = create_router(create_test_state()).unwrap();

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
        let app = create_router(create_test_state()).unwrap();

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
        let app = create_router(create_test_state()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

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
        let app = create_router(state.clone()).unwrap();

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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "deny");
    }

    #[tokio::test]
    async fn test_delete_validation_empty_relationships() {
        let app = create_router(create_test_state()).unwrap();

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
        let app = create_router(create_test_state()).unwrap();

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
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let delete_response: DeleteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(delete_response.relationships_deleted, 2);
    }

    #[tokio::test]
    async fn test_rate_limiting_disabled() {
        // Verify rate limiting can be disabled in configuration
        let state = create_test_state();
        assert!(!state.config.server.rate_limiting_enabled);

        let app = create_router(state).unwrap();

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
        let app = create_router(create_test_state()).unwrap();

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
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");
    }

    #[tokio::test]
    async fn test_delete_by_filter_resource() {
        // Test resource cleanup scenario: delete all relationships for a resource
        let state = create_test_state();
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

        // Parse SSE response
        let results = parse_sse_evaluate_response(&body).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "allow");
    }

    #[tokio::test]
    async fn test_delete_by_filter_with_limit() {
        // Test deletion with explicit limit
        let state = create_test_state();
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let delete_response: DeleteResponse = serde_json::from_slice(&body).unwrap();
        // Should only delete 2 relationships due to limit
        assert_eq!(delete_response.relationships_deleted, 2);
    }

    #[tokio::test]
    async fn test_delete_by_filter_combined_fields() {
        // Test deletion with multiple filter fields
        let state = create_test_state();
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let delete_response: DeleteResponse = serde_json::from_slice(&body).unwrap();
        // Should only delete the one matching relationship
        assert_eq!(delete_response.relationships_deleted, 1);
    }

    #[tokio::test]
    async fn test_delete_filter_empty_validation() {
        // Test that empty filter is rejected
        let app = create_router(create_test_state()).unwrap();

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
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

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
        let app = create_router(state.clone()).unwrap();

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
                    .body(Body::from(serde_json::to_string(&evaluate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

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
        let app = create_router(state.clone()).unwrap();

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let delete_response: DeleteResponse = serde_json::from_slice(&body).unwrap();
        // Should delete 2 for eve + 1 for frank = 3 total
        assert_eq!(delete_response.relationships_deleted, 3);
    }
}
