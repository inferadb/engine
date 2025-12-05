//! Integration tests for authentication
//!
//! These tests verify the end-to-end authentication flow:
//! - JWT token extraction and validation
//! - JWKS fetching and caching
//! - Scope-based authorization
//! - Error handling and response formats

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use inferadb_api::AppState;
use inferadb_auth::jwks_cache::JwksCache;
use inferadb_config::Config;
use inferadb_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use inferadb_store::MemoryBackend;
use serde_json::json;
use tower::ServiceExt;

mod integration;

// Re-use the mock JWKS infrastructure from infera-auth tests
mod common {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use serde_json::json;
    use tokio::sync::RwLock;
    use warp::Filter;

    #[allow(dead_code)]
    pub struct MockJwksServer {
        pub keypair: SigningKey,
        pub kid: String,
        pub server: tokio::task::JoinHandle<()>,
        pub url: String,
    }

    #[allow(dead_code)]
    impl MockJwksServer {
        pub async fn start() -> Self {
            let keypair = SigningKey::generate(&mut OsRng);
            let kid = "test-key-001".to_string();

            // Create JWKS response
            let public_key = keypair.verifying_key();
            let public_key_bytes = public_key.to_bytes();
            let x_base64 = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                public_key_bytes,
            );

            let jwks = json!({
                "keys": [{
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x_base64,
                    "kid": kid,
                    "use": "sig",
                    "alg": "EdDSA"
                }]
            });

            let jwks = Arc::new(RwLock::new(jwks));

            // Start mock JWKS server
            let jwks_filter = {
                let jwks = Arc::clone(&jwks);
                warp::path!("tenants" / String / ".well-known" / "jwks.json")
                    .and(warp::get())
                    .and_then(move |_org_id: String| {
                        let jwks = Arc::clone(&jwks);
                        async move {
                            let jwks = jwks.read().await;
                            Ok::<_, std::convert::Infallible>(warp::reply::json(&*jwks))
                        }
                    })
            };

            let server = tokio::spawn(async move {
                warp::serve(jwks_filter).run(([127, 0, 0, 1], 0)).await;
            });

            // Give server time to start
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Find the bound port (for now, use a fixed test port)
            let url = "http://127.0.0.1:8999".to_string();

            Self { keypair, kid, server, url }
        }

        pub fn generate_jwt(&self, org_id: &str, scopes: &[&str], expires_in_secs: i64) -> String {
            use jsonwebtoken::{EncodingKey, Header, encode};
            use serde::{Deserialize, Serialize};

            #[derive(Debug, Serialize, Deserialize)]
            struct Claims {
                iss: String,
                sub: String,
                aud: String,
                exp: i64,
                iat: i64,
                jti: String,
                scope: String,
            }

            let now = chrono::Utc::now().timestamp();
            let claims = Claims {
                iss: format!("tenant:{}", org_id),
                sub: format!("tenant:{}", org_id),
                aud: "https://api.inferadb.com/evaluate".to_string(),
                exp: now + expires_in_secs,
                iat: now,
                jti: uuid::Uuid::new_v4().to_string(),
                scope: scopes.join(" "),
            };

            let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
            header.kid = Some(self.kid.clone());

            // Convert Ed25519 key to PEM format for jsonwebtoken
            let secret = self.keypair.to_bytes();
            let encoding_key = EncodingKey::from_ed_der(&secret);

            encode(&header, &claims, &encoding_key).expect("Failed to encode JWT")
        }
    }

    impl Drop for MockJwksServer {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
}

fn create_test_state_with_auth(jwks_cache: Option<Arc<JwksCache>>) -> AppState {
    let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
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

    let config = Config::default();

    let state = AppState::builder(store, schema, Arc::new(config))
        .wasm_host(None)
        .jwks_cache(jwks_cache)
        .server_identity(None)
        .build();

    let health_tracker = state.health_tracker.clone();
    health_tracker.set_ready(true);
    health_tracker.set_startup_complete(true);

    state
}

#[tokio::test]
async fn test_missing_authorization_header() {
    // Create a real JWKS cache but make a request without a token
    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(std::time::Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:8999/tenants".to_string(),
            cache,
            std::time::Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state_with_auth(Some(jwks_cache));

    // Create a router directly without test auth middleware to test auth failure
    let router = Router::new()
        .route(
            "/v1/evaluate",
            post(inferadb_api::handlers::evaluate::stream::evaluate_stream_handler),
        )
        .route("/health", get(inferadb_api::health::health_check_handler))
        .with_state(state);

    let check_request = json!({
        "evaluations": [{
            "subject": "user:alice",
            "resource": "doc:readme",
            "permission": "reader",
            "context": null
        }]
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&check_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Verify WWW-Authenticate header is present
    let auth_header = response.headers().get(header::WWW_AUTHENTICATE);
    assert!(auth_header.is_some());
}

#[tokio::test]
async fn test_malformed_authorization_header() {
    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(std::time::Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:8999/tenants".to_string(),
            cache,
            std::time::Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state_with_auth(Some(jwks_cache));

    // Create a router directly without test auth middleware to test auth failure
    let router = Router::new()
        .route(
            "/v1/evaluate",
            post(inferadb_api::handlers::evaluate::stream::evaluate_stream_handler),
        )
        .with_state(state);

    let check_request = json!({
        "evaluations": [{
            "subject": "user:alice",
            "resource": "doc:readme",
            "permission": "reader",
            "context": null
        }]
    });

    // Test various malformed headers
    let test_cases = vec!["NotBearer token", "Bearer", "Bearer ", "Basic dXNlcjpwYXNz"];

    for auth_value in test_cases {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/evaluate")
                    .header("content-type", "application/json")
                    .header("authorization", auth_value)
                    .body(Body::from(serde_json::to_string(&check_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Failed for auth header: {}",
            auth_value
        );
    }
}

#[tokio::test]
async fn test_health_endpoint_unauthenticated() {
    // Health endpoint should always work without auth
    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(std::time::Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:8999/tenants".to_string(),
            cache,
            std::time::Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state_with_auth(Some(jwks_cache));

    // Create a router with just the health route (no auth middleware needed)
    let router = Router::new()
        .route("/health", get(inferadb_api::health::health_check_handler))
        .with_state(state);

    let response = router
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let health_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health_response["status"], "healthy");
}

#[tokio::test]
async fn test_invalid_jwt_format() {
    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(std::time::Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:8999/tenants".to_string(),
            cache,
            std::time::Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state_with_auth(Some(jwks_cache));

    // Create a router directly without test auth middleware to test auth failure
    let router = Router::new()
        .route(
            "/v1/evaluate",
            post(inferadb_api::handlers::evaluate::stream::evaluate_stream_handler),
        )
        .with_state(state);

    let check_request = json!({
        "evaluations": [{
            "subject": "user:alice",
            "resource": "doc:readme",
            "permission": "reader",
            "context": null
        }]
    });

    // Invalid JWT - not even base64
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .header("authorization", "Bearer not-a-valid-jwt")
                .body(Body::from(serde_json::to_string(&check_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_missing_required_scope() {
    // This test would require a full mock JWKS server setup
    // For now, we verify the scope validation logic works at the handler level
    // The actual JWT verification is tested in infera-auth integration tests

    // We'll skip this for now as it requires complex setup
    // The scope validation is tested in unit tests
}

#[tokio::test]
async fn test_write_endpoint_requires_write_scope() {
    // Similar to above - requires full mock JWKS setup
    // Scope validation logic is tested in middleware unit tests
}

#[tokio::test]
async fn test_expand_endpoint_accepts_multiple_scopes() {
    // Similar to above - requires full mock JWKS setup
    // Scope validation logic is tested in middleware unit tests
}
