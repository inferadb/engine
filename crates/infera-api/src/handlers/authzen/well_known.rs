//! AuthZEN configuration discovery endpoint
//!
//! Implements the `GET /.well-known/authzen-configuration` endpoint as specified
//! by the AuthZEN specification for service discovery and capability negotiation.

use axum::{Json, extract::State, http::header, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// AuthZEN configuration response
///
/// This structure represents the discovery metadata as specified by the AuthZEN
/// specification. It allows clients to discover available endpoints and extensions.
///
/// See: https://openid.github.io/authzen/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENConfiguration {
    /// The issuer identifier for this authorization service
    pub issuer: String,

    /// Core AuthZEN endpoints
    pub access_evaluation_endpoint: String,
    pub access_evaluations_endpoint: String,

    /// AuthZEN search endpoints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_resource_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_subject_endpoint: Option<String>,

    /// Supported entity types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_subject_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_resource_types: Option<Vec<String>>,

    /// InferaDB-specific extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthZENExtensions>,
}

/// InferaDB-specific extensions to the AuthZEN specification
///
/// These extensions provide additional ReBAC-specific functionality beyond
/// the core AuthZEN specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENExtensions {
    /// Relationship management extension (write, list, delete relationships)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferadb_relationship_management: Option<bool>,

    /// Relation expansion extension (visualize authorization graphs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferadb_relation_expansion: Option<bool>,

    /// Simulation extension (test authorization changes before applying)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferadb_simulation: Option<bool>,

    /// Real-time streaming extension (watch for relationship changes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferadb_realtime_streaming: Option<bool>,
}

/// Handler for `GET /.well-known/authzen-configuration`
///
/// Returns the AuthZEN configuration metadata for service discovery.
/// This endpoint is unauthenticated to allow clients to discover capabilities
/// before authenticating.
///
/// # Cache Headers
///
/// This endpoint returns `Cache-Control: public, max-age=3600` to allow
/// clients to cache the configuration for 1 hour, reducing unnecessary requests.
pub async fn get_authzen_configuration(State(state): State<AppState>) -> impl IntoResponse {
    // Construct the base URL from configuration
    let base_url = format!("http://{}:{}", state.config.server.host, state.config.server.port);

    // Build the configuration response
    let config = AuthZENConfiguration {
        issuer: base_url.clone(),
        access_evaluation_endpoint: format!("{}/access/v1/evaluation", base_url),
        access_evaluations_endpoint: format!("{}/access/v1/evaluations", base_url),
        search_resource_endpoint: Some(format!("{}/access/v1/search/resource", base_url)),
        search_subject_endpoint: Some(format!("{}/access/v1/search/subject", base_url)),
        supported_subject_types: Some(vec![
            "user".to_string(),
            "group".to_string(),
            "team".to_string(),
            "organization".to_string(),
            "service".to_string(),
            "role".to_string(),
        ]),
        supported_resource_types: Some(vec![
            "document".to_string(),
            "folder".to_string(),
            "file".to_string(),
            "project".to_string(),
            "repository".to_string(),
            "organization".to_string(),
            "team".to_string(),
            "workspace".to_string(),
        ]),
        extensions: Some(AuthZENExtensions {
            inferadb_relationship_management: Some(true),
            inferadb_relation_expansion: Some(true),
            inferadb_simulation: Some(true),
            inferadb_realtime_streaming: Some(true),
        }),
    };

    // Return JSON response with cache headers
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        Json(config),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use infera_config::Config;
    use infera_core::Evaluator;
    use infera_store::MemoryBackend;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::AppState;

    fn create_test_state() -> AppState {
        let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(infera_core::ipl::Schema::new(vec![]));
        // Use a test vault ID
        let test_vault = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let config = Arc::new(Config::default());
        let _health_tracker = Arc::new(crate::health::HealthTracker::new());

        AppState::new(
            store,
            schema,
            None, // No WASM host for tests
            config,
            None, // No JWKS cache for tests
            test_vault,
            Uuid::nil(),
        )
    }

    #[tokio::test]
    async fn test_authzen_configuration_endpoint() {
        let state = create_test_state();

        // Create a simple router just for this test
        use axum::{Router, routing::get};
        let app = Router::new()
            .route("/.well-known/authzen-configuration", get(get_authzen_configuration))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/authzen-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Debug: print response body if not OK
        if response.status() != StatusCode::OK {
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            eprintln!("Error response body: {}", String::from_utf8_lossy(&body));
            panic!("Expected 200 OK, got {}", status);
        }

        assert_eq!(response.status(), StatusCode::OK);

        // Check cache headers
        let cache_control = response.headers().get(header::CACHE_CONTROL);
        assert_eq!(cache_control.and_then(|v| v.to_str().ok()), Some("public, max-age=3600"));

        // Parse response body
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let config: AuthZENConfiguration = serde_json::from_slice(&body).unwrap();

        // Verify required fields
        assert!(config.issuer.contains("127.0.0.1"));
        assert!(config.access_evaluation_endpoint.ends_with("/access/v1/evaluation"));
        assert!(config.access_evaluations_endpoint.ends_with("/access/v1/evaluations"));
    }

    #[tokio::test]
    async fn test_configuration_includes_search_endpoints() {
        let state = create_test_state();

        use axum::{Router, routing::get};
        let app = Router::new()
            .route("/.well-known/authzen-configuration", get(get_authzen_configuration))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/authzen-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let config: AuthZENConfiguration = serde_json::from_slice(&body).unwrap();

        assert!(config.search_resource_endpoint.is_some());
        assert!(config.search_subject_endpoint.is_some());
        assert!(config.search_resource_endpoint.unwrap().ends_with("/access/v1/search/resource"));
        assert!(config.search_subject_endpoint.unwrap().ends_with("/access/v1/search/subject"));
    }

    #[tokio::test]
    async fn test_configuration_includes_supported_types() {
        let state = create_test_state();

        use axum::{Router, routing::get};
        let app = Router::new()
            .route("/.well-known/authzen-configuration", get(get_authzen_configuration))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/authzen-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let config: AuthZENConfiguration = serde_json::from_slice(&body).unwrap();

        // Verify subject types
        let subject_types = config.supported_subject_types.unwrap();
        assert!(subject_types.contains(&"user".to_string()));
        assert!(subject_types.contains(&"group".to_string()));
        assert!(subject_types.contains(&"team".to_string()));

        // Verify resource types
        let resource_types = config.supported_resource_types.unwrap();
        assert!(resource_types.contains(&"document".to_string()));
        assert!(resource_types.contains(&"folder".to_string()));
        assert!(resource_types.contains(&"project".to_string()));
    }

    #[tokio::test]
    async fn test_configuration_includes_extensions() {
        let state = create_test_state();

        use axum::{Router, routing::get};
        let app = Router::new()
            .route("/.well-known/authzen-configuration", get(get_authzen_configuration))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/authzen-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let config: AuthZENConfiguration = serde_json::from_slice(&body).unwrap();

        let extensions = config.extensions.unwrap();
        assert_eq!(extensions.inferadb_relationship_management, Some(true));
        assert_eq!(extensions.inferadb_relation_expansion, Some(true));
        assert_eq!(extensions.inferadb_simulation, Some(true));
        assert_eq!(extensions.inferadb_realtime_streaming, Some(true));
    }

    #[tokio::test]
    async fn test_configuration_json_structure() {
        let state = create_test_state();

        use axum::{Router, routing::get};
        let app = Router::new()
            .route("/.well-known/authzen-configuration", get(get_authzen_configuration))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/authzen-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

        // Verify it's valid JSON
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify key fields exist
        assert!(json["issuer"].is_string());
        assert!(json["access_evaluation_endpoint"].is_string());
        assert!(json["access_evaluations_endpoint"].is_string());
        assert!(json["extensions"].is_object());
    }
}
