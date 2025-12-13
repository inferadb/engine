//! # Infera API - REST and gRPC API Layer
//!
//! Exposes REST and gRPC endpoints for authorization checks (AuthZEN-compatible).

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Extension, Json, Router,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use inferadb_engine_auth::jwks_cache::JwksCache;
use inferadb_engine_config::Config;
use serde::Serialize;
use thiserror::Error;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor};
use tower_http::{compression::CompressionLayer, cors::CorsLayer};
use tracing::{info, warn};

pub mod adapters;
pub mod content_negotiation;
pub mod fdb_invalidation_watcher;
pub mod formatters;
pub mod grpc;
pub mod grpc_interceptor;
pub mod handlers;
pub mod health;
pub mod routes;
pub mod services;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
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
    Evaluation(#[from] inferadb_engine_core::EvalError),

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

impl From<inferadb_engine_auth::AuthError> for ApiError {
    fn from(err: inferadb_engine_auth::AuthError) -> Self {
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
    pub store: Arc<dyn inferadb_engine_store::InferaStore>,
    pub config: Arc<Config>,
    pub jwks_cache: Option<Arc<JwksCache>>,
    pub health_tracker: Arc<health::HealthTracker>,
    /// Server identity for signing engine-to-control requests
    pub server_identity: Option<Arc<inferadb_engine_control_client::ServerIdentity>>,

    // Shared cache for authorization decisions and expansions
    pub auth_cache: Arc<inferadb_engine_cache::AuthCache>,

    // Service layer (protocol-agnostic business logic)
    pub evaluation_service: Arc<services::EvaluationService>,
    pub resource_service: Arc<services::ResourceService>,
    pub subject_service: Arc<services::SubjectService>,
    pub relationship_service: Arc<services::RelationshipService>,
    pub expansion_service: Arc<services::ExpansionService>,
    pub watch_service: Arc<services::WatchService>,
}

/// Builder for AppState to avoid too many function arguments
pub struct AppStateBuilder {
    store: Arc<dyn inferadb_engine_store::InferaStore>,
    schema: Arc<inferadb_engine_core::ipl::Schema>,
    config: Arc<Config>,
    wasm_host: Option<Arc<inferadb_engine_wasm::WasmHost>>,
    jwks_cache: Option<Arc<JwksCache>>,
    server_identity: Option<Arc<inferadb_engine_control_client::ServerIdentity>>,
}

impl AppStateBuilder {
    /// Create a new AppStateBuilder with required parameters
    pub fn new(
        store: Arc<dyn inferadb_engine_store::InferaStore>,
        schema: Arc<inferadb_engine_core::ipl::Schema>,
        config: Arc<Config>,
    ) -> Self {
        Self { store, schema, config, wasm_host: None, jwks_cache: None, server_identity: None }
    }

    /// Set the WASM host
    pub fn wasm_host(mut self, wasm_host: Option<Arc<inferadb_engine_wasm::WasmHost>>) -> Self {
        self.wasm_host = wasm_host;
        self
    }

    /// Set the JWKS cache
    pub fn jwks_cache(mut self, jwks_cache: Option<Arc<JwksCache>>) -> Self {
        self.jwks_cache = jwks_cache;
        self
    }

    /// Set the server identity
    pub fn server_identity(
        mut self,
        server_identity: Option<Arc<inferadb_engine_control_client::ServerIdentity>>,
    ) -> Self {
        self.server_identity = server_identity;
        self
    }

    /// Build the AppState
    pub fn build(self) -> AppState {
        AppState::from_builder(self)
    }
}

impl AppState {
    /// Creates a new AppState builder
    pub fn builder(
        store: Arc<dyn inferadb_engine_store::InferaStore>,
        schema: Arc<inferadb_engine_core::ipl::Schema>,
        config: Arc<Config>,
    ) -> AppStateBuilder {
        AppStateBuilder::new(store, schema, config)
    }

    /// Internal constructor from builder
    fn from_builder(builder: AppStateBuilder) -> Self {
        let health_tracker = Arc::new(health::HealthTracker::new());

        // Create shared cache
        let auth_cache = if builder.config.cache.enabled {
            Arc::new(inferadb_engine_cache::AuthCache::new(
                builder.config.cache.capacity,
                std::time::Duration::from_secs(builder.config.cache.ttl),
            ))
        } else {
            // Create a minimal cache that won't be used
            Arc::new(inferadb_engine_cache::AuthCache::new(1, std::time::Duration::from_secs(1)))
        };

        // Determine which cache to pass to services
        let service_cache =
            if builder.config.cache.enabled { Some(Arc::clone(&auth_cache)) } else { None };

        // Create services with shared cache
        let evaluation_service = Arc::new(services::EvaluationService::new(
            Arc::clone(&builder.store) as Arc<dyn inferadb_engine_store::RelationshipStore>,
            Arc::clone(&builder.schema),
            builder.wasm_host.clone(),
            service_cache.clone(),
        ));

        let resource_service = Arc::new(services::ResourceService::new(
            Arc::clone(&builder.store) as Arc<dyn inferadb_engine_store::RelationshipStore>,
            Arc::clone(&builder.schema),
            builder.wasm_host.clone(),
            service_cache.clone(),
        ));

        let subject_service = Arc::new(services::SubjectService::new(
            Arc::clone(&builder.store) as Arc<dyn inferadb_engine_store::RelationshipStore>,
            Arc::clone(&builder.schema),
            builder.wasm_host.clone(),
            service_cache.clone(),
        ));

        let relationship_service = Arc::new(services::RelationshipService::new(
            Arc::clone(&builder.store) as Arc<dyn inferadb_engine_store::RelationshipStore>,
            Arc::clone(&builder.schema),
            builder.wasm_host.clone(),
            service_cache.clone(),
        ));

        let expansion_service = Arc::new(services::ExpansionService::new(
            Arc::clone(&builder.store) as Arc<dyn inferadb_engine_store::RelationshipStore>,
            Arc::clone(&builder.schema),
            builder.wasm_host.clone(),
            service_cache,
        ));

        let watch_service = Arc::new(services::WatchService::new(
            Arc::clone(&builder.store) as Arc<dyn inferadb_engine_store::RelationshipStore>
        ));

        Self {
            store: builder.store,
            config: builder.config,
            jwks_cache: builder.jwks_cache,
            health_tracker,
            server_identity: builder.server_identity,
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

/// Custom key extractor for rate limiting that provides a fallback IP for tests
/// In production, extracts the peer IP from the connection
/// In tests (where there's no peer connection), uses a default IP
#[derive(Clone, Default)]
struct SmartIpKeyExtractor;

impl KeyExtractor for SmartIpKeyExtractor {
    type Key = SocketAddr;

    fn extract<T>(
        &self,
        req: &axum::http::Request<T>,
    ) -> std::result::Result<Self::Key, tower_governor::errors::GovernorError> {
        // Try to get peer IP from connection info extension
        // If not available (e.g., in tests), use a fallback IP
        Ok(req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|connect_info| connect_info.0)
            .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()))
    }
}

/// Create public routes (client-facing endpoints)
/// These routes accept client JWTs and handle authorization requests
pub async fn public_routes(components: ServerComponents) -> Result<Router> {
    // Create AppState with services
    let state = components.create_app_state();

    // Configure rate limiting: 1000 requests per minute per IP
    // Based on docs/RATE_LIMITING.md recommendations
    // Uses custom key extractor that works in both production and tests
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1000 / 60) // 1000 requests per minute = ~16.67 per second
            .burst_size(2000) // Allow bursts up to 2000 requests
            .key_extractor(SmartIpKeyExtractor)
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
        // Organization management routes
        .route(
            "/v1/organizations",
            post(handlers::organizations::create::create_organization)
                .get(handlers::organizations::list::list_organizations),
        )
        .route(
            "/v1/organizations/{id}",
            axum::routing::get(handlers::organizations::get::get_organization)
                .patch(handlers::organizations::update::update_organization)
                .delete(handlers::organizations::delete::delete_organization),
        )
        // Vault management routes
        .route(
            "/v1/organizations/{organization_id}/vaults",
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

    // Type alias for complex auth components tuple (reduces clippy::type_complexity)
    type AuthComponents = (
        Arc<dyn inferadb_engine_control_client::VaultVerifier>,
        Option<Arc<inferadb_engine_auth::CertificateCache>>,
        Option<Arc<inferadb_engine_control_client::ControlVaultVerifier>>,
    );

    // Get effective mesh URL
    let effective_mesh_url = state.config.effective_mesh_url();

    // Create VaultVerifier and CertificateCache instances based on configuration
    let (vault_verifier, cert_cache, _ctrl_vault_verifier): AuthComponents = if !effective_mesh_url
        .is_empty()
    {
        // Check if discovery is enabled for Control
        let control_client = if matches!(
            state.config.discovery.mode,
            inferadb_engine_config::DiscoveryMode::Kubernetes
        ) {
            // Discovery enabled - create discovery service and load balancing client
            info!("Control discovery ENABLED - mode: {:?}", state.config.discovery.mode);

            // Create discovery service based on mode (Kubernetes only)
            let discovery: Arc<dyn inferadb_engine_discovery::EndpointDiscovery> =
                match &state.config.discovery.mode {
                    inferadb_engine_config::DiscoveryMode::Kubernetes => Arc::new(
                        inferadb_engine_discovery::KubernetesServiceDiscovery::new()
                            .await
                            .map_err(|e| {
                                ApiError::Internal(format!(
                                    "Failed to create Kubernetes discovery: {}",
                                    e
                                ))
                            })?,
                    ),
                    inferadb_engine_config::DiscoveryMode::None => unreachable!(),
                };

            // Perform initial discovery to get endpoints
            let initial_endpoints = discovery.discover(&effective_mesh_url).await.map_err(|e| {
                ApiError::Internal(format!("Initial endpoint discovery failed: {}", e))
            })?;

            info!("Discovered {} Control endpoints", initial_endpoints.len());

            // Create load balancing client with discovered endpoints
            let lb_client =
                Arc::new(inferadb_engine_discovery::LoadBalancingClient::new(initial_endpoints));

            // Create discovery refresher for background updates
            let refresher = Arc::new(inferadb_engine_discovery::DiscoveryRefresher::new(
                Arc::clone(&discovery),
                Arc::clone(&lb_client),
                state.config.discovery.cache_ttl,
                effective_mesh_url.clone(),
            ));

            // Spawn background refresh task
            Arc::clone(&refresher).spawn();
            info!(
                "Discovery refresh task spawned (interval: {}s)",
                state.config.discovery.cache_ttl
            );

            // Create ControlClient with load balancing
            Arc::new(
                inferadb_engine_control_client::ControlClient::new(
                    effective_mesh_url.clone(),
                    None, // Internal URL same as url
                    state.config.mesh.timeout,
                    Some(lb_client),
                    state.server_identity.clone(),
                )
                .map_err(|e| {
                    ApiError::Internal(format!(
                        "Failed to create load-balanced Control client: {}",
                        e
                    ))
                })?,
            )
        } else {
            // Discovery disabled - use static URL (Kubernetes service handles load balancing)
            Arc::new(
                inferadb_engine_control_client::ControlClient::new(
                    effective_mesh_url.clone(),
                    None, // Internal URL same as url
                    state.config.mesh.timeout,
                    None,
                    state.server_identity.clone(),
                )
                .map_err(|e| {
                    ApiError::Internal(format!("Failed to create Control client: {}", e))
                })?,
            )
        };

        let ctrl_verifier = Arc::new(inferadb_engine_control_client::ControlVaultVerifier::new(
            Arc::clone(&control_client),
            std::time::Duration::from_secs(300), // 5 min vault cache TTL
            std::time::Duration::from_secs(600), // 10 min org cache TTL
        ));

        let cert_cache = Arc::new(
            inferadb_engine_auth::CertificateCache::new(
                effective_mesh_url.clone(),
                std::time::Duration::from_secs(300), // 5 min cert cache TTL
                1000,                                // Max 1000 cached certificates
            )
            .map_err(|e| {
                ApiError::Internal(format!("Failed to create certificate cache: {}", e))
            })?,
        );

        // Keep both trait object and concrete type references
        let vault_verifier_trait: Arc<dyn inferadb_engine_control_client::VaultVerifier> =
            Arc::clone(&ctrl_verifier) as Arc<dyn inferadb_engine_control_client::VaultVerifier>;

        (vault_verifier_trait, Some(cert_cache), Some(ctrl_verifier))
    } else {
        // Use no-op verifier when management API not configured
        warn!("○ Vault caching disabled");
        warn!("  For more information, see https://inferadb.com/docs/?search=auth.control_url");
        (
            Arc::new(inferadb_engine_control_client::NoOpVaultVerifier)
                as Arc<dyn inferadb_engine_control_client::VaultVerifier>,
            None,
            None,
        )
    };

    // Apply authentication middleware
    let protected_routes = if let Some(jwks_cache) = &state.jwks_cache {
        let jwks_cache = Arc::clone(jwks_cache);

        // Apply auth middleware first, then vault validation middleware
        // Note: Layers are applied in reverse order, so vault validation runs after auth
        let vault_verifier_clone = Arc::clone(&vault_verifier);
        let cert_cache_clone = cert_cache.clone();
        let jwks_cache_clone = Arc::clone(&jwks_cache);
        protected_routes
            .layer(axum::middleware::from_fn(move |req, next| {
                let verifier = Arc::clone(&vault_verifier_clone);
                async move {
                    inferadb_engine_auth::enhanced_vault_validation_middleware(verifier).await(
                        req, next,
                    )
                    .await
                }
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let jwks_cache = Arc::clone(&jwks_cache_clone);
                let cert_cache = cert_cache_clone.clone();
                async move {
                    inferadb_engine_auth::middleware::auth_middleware(
                        jwks_cache, cert_cache, req, next,
                    )
                    .await
                }
            }))
    } else {
        return Err(ApiError::Internal(
            "JWKS cache is required but not initialized. Authentication cannot be disabled."
                .to_string(),
        ));
    };

    // Combine health endpoints, public discovery, and protected routes
    // Health endpoints follow Kubernetes API server conventions (/livez, /readyz, /startupz,
    // /healthz) Note: AuthZEN /access/v1/* endpoints are now in protected_routes for vault
    // isolation
    let router = Router::new()
        .route("/livez", get(health::livez_handler))
        .route("/readyz", get(health::readyz_handler))
        .route("/startupz", get(health::startupz_handler))
        .route("/healthz", get(health::healthz_handler))
        // AuthZEN configuration endpoint (public for service discovery)
        .route(
            "/.well-known/authzen-configuration",
            get(handlers::authzen::well_known::get_authzen_configuration),
        )
        .merge(protected_routes)
        .with_state(state.clone());

    // Add CORS, compression, and rate limiting layers
    // Note: Rate limiting is applied to all routes including health endpoints
    let router = router
        .layer(governor_layer)
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .layer(CompressionLayer::new());

    // Mark service as ready to accept traffic
    state.health_tracker.set_ready(true);
    state.health_tracker.set_startup_complete(true);

    Ok(router)
}

// Health check handlers moved to health.rs module

/// Create internal routes (server-to-server communication)
/// Exposes JWKS endpoint (no auth) and privileged cache invalidation endpoints (Control JWT
/// auth)
pub async fn internal_routes(components: ServerComponents) -> Result<Router> {
    // Create AppState
    let state = components.create_app_state();

    // Public routes (no authentication required):
    // - JWKS endpoint: Control fetches server public keys from here
    // - Metrics endpoint: Prometheus scrapes metrics from here
    let public_internal_routes = Router::new()
        .route("/.well-known/jwks.json", get(handlers::jwks::get_server_jwks))
        .route("/metrics", get(handlers::internal::metrics_handler))
        .with_state(state.clone());

    // Get effective mesh URL
    let effective_mesh_url = state.config.effective_mesh_url();

    // Privileged cache invalidation routes (require Control JWT authentication)
    // These are only enabled when management API is configured
    let privileged_routes = if !effective_mesh_url.is_empty() {
        // Create aggregated Control JWKS cache for verifying Control JWTs
        // This cache supports discovery and aggregates keys from all Control instances
        let control_jwks_cache = Arc::new(inferadb_engine_auth::AggregatedControlJwksCache::new(
            state.config.discovery.mode.clone(),
            effective_mesh_url.clone(),
            std::time::Duration::from_secs(900), // 15 minutes TTL
        ));

        // Create ControlVaultVerifier for cache invalidation handlers
        // This requires creating a ControlClient first
        let control_client = Arc::new(
            inferadb_engine_control_client::ControlClient::new(
                effective_mesh_url.clone(),
                None, // Internal URL same as url
                state.config.mesh.timeout,
                None,
                state.server_identity.clone(),
            )
            .map_err(|e| ApiError::Internal(format!("Failed to create Control client: {}", e)))?,
        );

        let ctrl_verifier = Arc::new(inferadb_engine_control_client::ControlVaultVerifier::new(
            Arc::clone(&control_client),
            std::time::Duration::from_secs(300), // 5 min vault cache TTL
            std::time::Duration::from_secs(600), // 10 min org cache TTL
        ));

        // Create certificate cache for internal routes
        let cert_cache = Arc::new(
            inferadb_engine_auth::CertificateCache::new(
                effective_mesh_url.clone(),
                std::time::Duration::from_secs(300), // 5 min cert cache TTL
                1000,                                // Max 1000 cached certificates
            )
            .map_err(|e| {
                ApiError::Internal(format!("Failed to create certificate cache: {}", e))
            })?,
        );

        // Create internal router with Control JWT auth middleware and vault verifier extension
        let ctrl_cache_clone = Arc::clone(&control_jwks_cache);
        let verifier_clone = Arc::clone(&ctrl_verifier);
        let cert_cache_clone = Arc::clone(&cert_cache);
        Some(
            Router::new()
                .route(
                    "/internal/cache/invalidate/vault/{vault_id}",
                    post(handlers::internal::invalidate_vault_cache),
                )
                .route(
                    "/internal/cache/invalidate/organization/{org_id}",
                    post(handlers::internal::invalidate_organization_cache),
                )
                .route("/internal/cache/invalidate/all", post(handlers::internal::clear_all_caches))
                .route(
                    "/internal/cache/invalidate/certificate/{org_id}/{client_id}/{cert_id}",
                    post(handlers::internal::invalidate_certificate_cache),
                )
                // Add vault verifier and cert cache as Extensions for handlers
                .layer(Extension(verifier_clone))
                .layer(Extension(cert_cache_clone))
                // Apply Control JWT auth middleware (discovery-aware)
                .layer(axum::middleware::from_fn(move |req, next| {
                    let cache = Arc::clone(&ctrl_cache_clone);
                    async move {
                        inferadb_engine_auth::aggregated_control_auth_middleware(cache, req, next)
                            .await
                    }
                }))
                .with_state(state.clone()),
        )
    } else {
        warn!("○ Cache invalidation endpoints disabled");
        warn!("  For more information, see https://inferadb.com/docs/?search=auth.control_url");
        None
    };

    // Combine public (no auth) and privileged routes (Control JWT auth)
    let router = if let Some(privileged) = privileged_routes {
        public_internal_routes.merge(privileged)
    } else {
        public_internal_routes
    };

    Ok(router)
}

/// Serve the public router on the configured address
pub async fn serve_public(
    components: ServerComponents,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let router = public_routes(components).await?;

    axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}

/// Serve the internal router on the configured address
pub async fn serve_internal(
    components: ServerComponents,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let router = internal_routes(components).await?;

    axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}

/// Configuration for starting server components
pub struct ServerComponents {
    pub store: Arc<dyn inferadb_engine_store::InferaStore>,
    pub schema: Arc<inferadb_engine_core::ipl::Schema>,
    pub wasm_host: Option<Arc<inferadb_engine_wasm::WasmHost>>,
    pub config: Arc<Config>,
    pub jwks_cache: Option<Arc<JwksCache>>,
    pub server_identity: Option<Arc<inferadb_engine_control_client::ServerIdentity>>,
}

impl ServerComponents {
    /// Create AppState from components
    fn create_app_state(&self) -> AppState {
        AppState::builder(
            Arc::clone(&self.store),
            Arc::clone(&self.schema),
            Arc::clone(&self.config),
        )
        .wasm_host(self.wasm_host.clone())
        .jwks_cache(self.jwks_cache.clone())
        .server_identity(self.server_identity.clone())
        .build()
    }
}

/// Start the gRPC server
pub async fn serve_grpc(components: ServerComponents) -> anyhow::Result<()> {
    use grpc::proto::inferadb_service_server::InferadbServiceServer;
    use tonic::transport::Server;

    // Create AppState with services
    let state = components.create_app_state();

    // Mark service as ready to accept traffic
    state.health_tracker.set_ready(true);
    state.health_tracker.set_startup_complete(true);

    let service = grpc::InferadbServiceImpl::new(state.clone());

    let addr = components.config.listen.grpc.parse()?;

    // Set up reflection service
    let file_descriptor_set = tonic::include_file_descriptor_set!("inferadb_descriptor");
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(file_descriptor_set)
        .build_v1()?;

    info!("gRPC reflection enabled");

    // Authentication is always required
    let cache = state.jwks_cache.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "JWKS cache is required but not initialized. Authentication cannot be disabled."
        )
    })?;

    info!("Starting gRPC server on {} with authentication enabled", addr);

    // Try to load internal JWKS from well-known environment variable
    // Internal service authentication is optional; if INFERADB_INTERNAL_JWKS is not set, it's
    // skipped
    let internal_loader =
        inferadb_engine_auth::InternalJwksLoader::from_config(None, Some("INFERADB_INTERNAL_JWKS"))
            .ok()
            .map(Arc::new);

    if internal_loader.is_some() {
        info!("Internal JWT authentication enabled for gRPC");
    }

    // Create auth interceptor
    let interceptor = grpc_interceptor::AuthInterceptor::new(
        Arc::clone(cache),
        internal_loader,
        Arc::new(components.config.token.clone()),
    );

    // Add service with interceptor and reflection
    Server::builder()
        .add_service(InferadbServiceServer::with_interceptor(service, interceptor))
        .add_service(reflection_service)
        .serve(addr)
        .await?;

    Ok(())
}

/// Creates a test router for integration tests.
///
/// This router exposes the same endpoints as production but without JWT authentication
/// middleware. Tests should use the test auth middleware from the integration test
/// framework to inject authentication context.
///
/// # Example
///
/// ```ignore
/// use inferadb_engine_api::{create_test_router, AppState};
/// use inferadb_engine_api::test_utils::with_test_auth;
///
/// let state = create_test_state();
/// let router = create_test_router(state.clone()).await.unwrap();
/// let authenticated_router = with_test_auth(router);
/// ```
///
/// # Security Warning
///
/// This function should only be used in test code. Production code should use
/// `public_routes()` or `internal_routes()` which include proper JWT authentication.
#[cfg(any(test, feature = "test-utils"))]
pub async fn create_test_router(state: AppState) -> Result<Router> {
    use axum::routing::{get, post};
    use handlers::{
        evaluate::stream::evaluate_stream_handler,
        expand::stream::expand_handler,
        relationships::{
            delete::delete_relationships_handler, list::list_relationships_stream_handler,
            write::write_relationships_handler,
        },
        resources::list::list_resources_stream_handler,
        subjects::list::list_subjects_stream_handler,
    };

    // Create a simple router for tests (without rate limiting or JWT auth)
    // Tests should use the test auth middleware to inject authentication context
    let router = Router::new()
        .route("/v1/evaluate", post(evaluate_stream_handler))
        .route("/v1/expand", post(expand_handler))
        .route("/v1/resources/list", post(list_resources_stream_handler))
        .route("/v1/relationships/list", post(list_relationships_stream_handler))
        .route("/v1/subjects/list", post(list_subjects_stream_handler))
        .route("/v1/relationships/write", post(write_relationships_handler))
        .route("/v1/relationships/delete", post(delete_relationships_handler))
        .route(
            "/v1/relationships/{resource}/{relation}/{subject}",
            get(handlers::relationships::get::get_relationship),
        )
        // Organization management routes (for content negotiation tests)
        .route("/v1/organizations/{id}", get(handlers::organizations::get::get_organization))
        // Vault management routes (for content negotiation tests)
        .route("/v1/vaults/{id}", get(handlers::vaults::get::get_vault))
        // Health endpoints (Kubernetes conventions)
        .route("/livez", get(health::livez_handler))
        .route("/readyz", get(health::readyz_handler))
        .route("/startupz", get(health::startupz_handler))
        .route("/healthz", get(health::healthz_handler))
        .with_state(state);

    Ok(router)
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        extract::Request as AxumRequest,
        http::{Request, StatusCode},
        middleware,
        response::Response,
    };
    use handlers::relationships::{delete::DeleteResponse, write::WriteResponse};
    use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
    use inferadb_engine_store::MemoryBackend;
    use inferadb_engine_types::{AuthContext, AuthMethod, UsersetNodeType, UsersetTree};
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;

    fn create_test_state() -> (AppState, Arc<Schema>) {
        let store: Arc<dyn inferadb_engine_store::InferaStore> = Arc::new(MemoryBackend::new());
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

        let config = Arc::new(inferadb_engine_config::Config::default());

        let state = AppState::builder(store, Arc::clone(&schema), config)
            .wasm_host(None)
            .jwks_cache(None)
            .server_identity(None)
            .build();

        (state, schema)
    }

    /// Create a default test auth context with admin permissions
    fn create_test_auth_context(vault: i64, organization: i64) -> AuthContext {
        AuthContext {
            client_id: "test_client".to_string(),
            key_id: "test_key".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: vec![
                "inferadb.admin".to_string(),
                "inferadb.check".to_string(),
                "inferadb.write".to_string(),
                "inferadb.expand".to_string(),
                "inferadb.list_subjects".to_string(),
                "inferadb.list_resources".to_string(),
                "inferadb.list_relationships".to_string(),
            ],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: Some("test_jti".to_string()),
            vault,
            organization,
        }
    }

    /// Test middleware that injects an AuthContext into request extensions
    async fn test_auth_middleware(
        auth_context: AuthContext,
        mut request: AxumRequest<Body>,
        next: axum::middleware::Next,
    ) -> Response {
        request.extensions_mut().insert(Arc::new(auth_context));
        next.run(request).await
    }

    /// Wrap a router with test authentication using hardcoded test values
    fn with_test_auth(router: Router, vault: i64, organization: i64) -> Router {
        let auth = create_test_auth_context(vault, organization);
        router.layer(middleware::from_fn(move |req, next| {
            let auth_clone = auth.clone();
            async move { test_auth_middleware(auth_clone, req, next).await }
        }))
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

    /// Helper function for tests to create an authenticated router from AppState
    async fn create_router(state: AppState, _schema: Arc<Schema>) -> Result<Router> {
        // Use fixed test values for vault and organization
        let vault = 1i64;
        let organization = 2i64;

        // Create test router and wrap with test auth middleware
        let router = create_test_router(state).await?;
        Ok(with_test_auth(router, vault, organization))
    }

    #[tokio::test]
    async fn test_health_check() {
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

        let response = app
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_check_deny() {
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
    async fn test_lookup_resources_validation() {
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state, schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
        let (state, schema) = create_test_state();
        let app = create_router(state.clone(), schema).await.unwrap();

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
