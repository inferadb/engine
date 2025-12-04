//! Integration tests for content negotiation (JSON vs TOON format)

mod integration;

use std::sync::atomic::{AtomicI64, Ordering};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use inferadb_types::{Organization, Vault, VaultResponse};
use serde_json::json;
use tower::ServiceExt;

static TEST_ID_COUNTER: AtomicI64 = AtomicI64::new(10000000000000);

fn generate_test_id() -> i64 {
    TEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Helper to create test app state with organization and authenticated router
async fn create_test_app() -> (inferadb_api::AppState, Router) {
    let state = integration::create_test_state();

    // Create the default organization
    let organization =
        Organization::with_id(state.default_organization, "Test Organization".to_string());
    state
        .store
        .create_organization(organization)
        .await
        .expect("Failed to create test organization");

    // Create test router with authentication middleware
    // We create the router manually here since create_test_router is only available in tests
    let router = Router::new()
        .route(
            "/v1/evaluate",
            post(inferadb_api::handlers::evaluate::stream::evaluate_stream_handler),
        )
        .route("/v1/vaults/{id}", get(inferadb_api::handlers::vaults::get::get_vault))
        .route(
            "/v1/organizations/{id}",
            get(inferadb_api::handlers::organizations::get::get_organization),
        )
        .route("/health", get(inferadb_api::health::health_check_handler))
        .with_state(state.clone());
    let authenticated_router =
        integration::with_test_auth(router, state.default_vault, state.default_organization);

    (state, authenticated_router)
}

#[tokio::test]
async fn test_json_format_explicit() {
    let (state, app) = create_test_app().await;

    // Create a vault first
    let vault_id = generate_test_id();
    let vault = Vault::with_id(vault_id, state.default_organization, "Test Vault".to_string());
    state.store.create_vault(vault).await.unwrap();

    // Request with explicit JSON Accept header
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", vault_id))
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Verify response
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");

    // Verify body is valid JSON
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let vault_response: VaultResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(vault_response.id, vault_id);
}

#[tokio::test]
async fn test_toon_format_explicit() {
    let (state, app) = create_test_app().await;

    // Create a vault first
    let vault_id = generate_test_id();
    let vault = Vault::with_id(vault_id, state.default_organization, "Test Vault".to_string());
    state.store.create_vault(vault).await.unwrap();

    // Request with TOON Accept header
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", vault_id))
        .header(header::ACCEPT, "text/toon")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Verify response
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/toon");

    // Verify body is TOON format (should be plain text, not JSON)
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = std::str::from_utf8(&body).unwrap();

    // TOON format should NOT start with `{` like JSON
    assert!(!body_str.trim().starts_with('{'));
    // TOON format should contain the vault ID
    assert!(body_str.contains(&vault_id.to_string()));
}

#[tokio::test]
async fn test_default_format_is_json() {
    let (state, app) = create_test_app().await;

    // Create a vault first
    let vault_id = generate_test_id();
    let vault = Vault::with_id(vault_id, state.default_organization, "Test Vault".to_string());
    state.store.create_vault(vault).await.unwrap();

    // Request with NO Accept header (should default to JSON)
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", vault_id))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Verify response defaults to JSON
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
}

#[tokio::test]
async fn test_wildcard_accept_defaults_to_json() {
    let (state, app) = create_test_app().await;

    // Create a vault first
    let vault_id = generate_test_id();
    let vault = Vault::with_id(vault_id, state.default_organization, "Test Vault".to_string());
    state.store.create_vault(vault).await.unwrap();

    // Request with wildcard Accept header
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", vault_id))
        .header(header::ACCEPT, "*/*")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Verify response defaults to JSON
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
}

#[tokio::test]
async fn test_quality_value_priority_json_higher() {
    let (state, app) = create_test_app().await;

    // Create a vault first
    let vault_id = generate_test_id();
    let vault = Vault::with_id(vault_id, state.default_organization, "Test Vault".to_string());
    state.store.create_vault(vault).await.unwrap();

    // Request with JSON having higher priority
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", vault_id))
        .header(header::ACCEPT, "application/json;q=1.0, text/toon;q=0.5")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return JSON (higher priority)
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
}

#[tokio::test]
async fn test_quality_value_priority_toon_higher() {
    let (state, app) = create_test_app().await;

    // Create a vault first
    let vault_id = generate_test_id();
    let vault = Vault::with_id(vault_id, state.default_organization, "Test Vault".to_string());
    state.store.create_vault(vault).await.unwrap();

    // Request with TOON having higher priority
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", vault_id))
        .header(header::ACCEPT, "text/toon;q=1.0, application/json;q=0.5")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return TOON (higher priority)
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/toon");
}

#[tokio::test]
async fn test_streaming_endpoint_rejects_toon() {
    let (_state, app) = create_test_app().await;

    // Request streaming endpoint with TOON format
    let request = Request::builder()
        .method("POST")
        .uri("/v1/evaluate")
        .header(header::ACCEPT, "text/toon")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "evaluations": [{
                    "subject": "user:alice",
                    "resource": "document:1",
                    "permission": "view"
                }]
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return Bad Request (400)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Verify error message mentions streaming endpoints don't support TOON
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(body_str.contains("Streaming endpoints do not support TOON"));
}

#[tokio::test]
async fn test_streaming_endpoint_accepts_json() {
    let (_state, app) = create_test_app().await;

    // Request streaming endpoint with JSON format
    let request = Request::builder()
        .method("POST")
        .uri("/v1/evaluate")
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "evaluations": [{
                    "subject": "user:alice",
                    "resource": "document:1",
                    "permission": "view"
                }]
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should succeed (streaming starts)
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/event-stream");
}

#[tokio::test]
async fn test_error_responses_always_json() {
    let (_state, app) = create_test_app().await;

    // Request non-existent vault with TOON Accept header
    let non_existent_vault = generate_test_id();
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", non_existent_vault))
        .header(header::ACCEPT, "text/toon")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return 404
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Error responses are always JSON (as documented in ApiError implementation)
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");

    // Verify error body is valid JSON
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(error.get("error").is_some());
}

#[tokio::test]
async fn test_multiple_endpoints_support_toon() {
    let (state, app) = create_test_app().await;

    // Create test data
    let vault_id = generate_test_id();
    let organization_id = state.default_organization;
    let vault = Vault::with_id(vault_id, organization_id, "Test Vault".to_string());
    state.store.create_vault(vault).await.unwrap();

    // Test vault endpoint
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/vaults/{}", vault_id))
        .header(header::ACCEPT, "text/toon")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/toon");

    // Test organization endpoint
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/organizations/{}", organization_id))
        .header(header::ACCEPT, "text/toon")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/toon");
}
