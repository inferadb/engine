//! Integration tests for gRPC authentication
//!
//! These tests verify the end-to-end gRPC authentication flow:
//! - Bearer token extraction from gRPC metadata
//! - Tenant JWT validation via JWKS
//! - Internal JWT validation via InternalJwksLoader
//! - AuthContext injection into request extensions
//! - Error handling and gRPC status codes

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use inferadb_engine_api::{
    AppState,
    grpc::proto::{
        EvaluateRequest as ProtoEvaluateRequest, inferadb_service_client::InferadbServiceClient,
    },
};
use inferadb_engine_auth::{internal::InternalJwksLoader, jwks_cache::JwksCache};
use inferadb_engine_config::Config;
use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use inferadb_engine_store::MemoryBackend;
// Re-use test helpers from test fixtures
use inferadb_engine_test_fixtures::{
    InternalClaims, create_internal_jwks, generate_internal_jwt, generate_internal_keypair,
};
use tonic::{
    Code, Request,
    metadata::MetadataValue,
    transport::{Channel, Server},
};

mod common {
    use std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, Mutex, OnceLock},
    };

    use axum::{Json, Router, extract::Path, routing::get};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rand_core::OsRng;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tokio::task::JoinHandle;

    /// Type alias for keypair storage to satisfy clippy::type_complexity
    type KeypairStorage = Arc<Mutex<HashMap<String, (SigningKey, String)>>>;

    /// Thread-safe storage for test keypairs
    static TEST_KEYPAIRS: OnceLock<KeypairStorage> = OnceLock::new();

    /// Get or create a keypair for a tenant
    fn get_test_keypair_for_tenant(tenant: &str) -> (SigningKey, String) {
        let keypairs = TEST_KEYPAIRS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())));

        let mut map = keypairs.lock().unwrap();
        if let Some(key) = map.get(tenant) {
            key.clone()
        } else {
            let signing_key = SigningKey::generate(&mut OsRng);
            let kid = format!("{}-key-001", tenant);
            map.insert(tenant.to_string(), (signing_key.clone(), kid.clone()));
            (signing_key, kid)
        }
    }

    /// Convert Ed25519 public key to JWK JSON
    fn public_key_to_jwk_json(kid: &str, public_key: &VerifyingKey) -> serde_json::Value {
        let x = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            public_key.as_bytes(),
        );

        json!({
            "kty": "OKP",
            "use": "sig",
            "kid": kid,
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": x
        })
    }

    /// Mock JWKS endpoint handler
    async fn jwks_handler(Path(tenant_json): Path<String>) -> Json<serde_json::Value> {
        // Extract tenant from "{tenant}.json"
        let tenant = tenant_json.strip_suffix(".json").unwrap_or(&tenant_json);

        // Get or generate keypair for this tenant
        let (signing_key, kid) = get_test_keypair_for_tenant(tenant);
        let verifying_key = signing_key.verifying_key();

        // Convert to JWK
        let jwk = public_key_to_jwk_json(&kid, &verifying_key);

        Json(json!({
            "keys": [jwk]
        }))
    }

    /// Mock JWKS server for tenant JWT testing
    pub struct MockJwksServer {
        pub base_url: String,
        pub server: JoinHandle<()>,
    }

    impl MockJwksServer {
        pub async fn start() -> Self {
            let app =
                Router::new().route("/v1/organizations/{tenant}/jwks.json", get(jwks_handler));

            // Bind to random port
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            let local_addr = listener.local_addr().unwrap();
            let base_url = format!("http://{}", local_addr);

            // Spawn server
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            Self { base_url, server }
        }

        pub fn generate_tenant_jwt(
            &self,
            org_id: &str,
            scopes: &[&str],
            expires_in_secs: i64,
        ) -> String {
            #[derive(Debug, Serialize, Deserialize)]
            struct Claims {
                iss: String,
                sub: String,
                aud: String,
                exp: u64,
                iat: u64,
                jti: String,
                scope: String,
                org_id: String,
                vault_id: String,
            }

            let (signing_key, kid) = get_test_keypair_for_tenant(org_id);

            let now = chrono::Utc::now().timestamp();
            let claims = Claims {
                iss: format!("tenant:{}", org_id),
                sub: format!("tenant:{}", org_id),
                aud: "https://api.inferadb.com/evaluate".to_string(),
                exp: (now + expires_in_secs) as u64,
                iat: now as u64,
                jti: uuid::Uuid::new_v4().to_string(),
                scope: scopes.join(" "),
                org_id: org_id.to_string(),
                vault_id: "12345678901234".to_string(), // Test vault ID
            };

            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some(kid);

            // Create PKCS#8 DER encoding for Ed25519
            let private_bytes = signing_key.to_bytes();
            let mut pkcs8_der = vec![
                0x30, 0x2e, // SEQUENCE, 46 bytes
                0x02, 0x01, 0x00, // INTEGER version 0
                0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
                0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
                0x04, 0x22, // OCTET STRING, 34 bytes
                0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
            ];
            pkcs8_der.extend_from_slice(&private_bytes);

            // Convert to PEM
            let pem = format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pkcs8_der)
            );

            let encoding_key =
                EncodingKey::from_ed_pem(pem.as_bytes()).expect("Failed to create encoding key");

            encode(&header, &claims, &encoding_key).expect("Failed to encode JWT")
        }
    }

    impl Drop for MockJwksServer {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
}

fn create_test_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![TypeDef::new(
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
    )]))
}

fn create_test_state(jwks_cache: Option<Arc<JwksCache>>) -> AppState {
    let store: Arc<dyn inferadb_engine_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();

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

/// Start a gRPC server with authentication enabled
async fn start_grpc_server_with_auth(
    state: AppState,
    internal_loader: Option<Arc<InternalJwksLoader>>,
) -> (tokio::task::JoinHandle<()>, u16) {
    use inferadb_engine_api::{
        grpc::{InferadbServiceImpl, proto::inferadb_service_server::InferadbServiceServer},
        grpc_interceptor::AuthInterceptor,
    };

    let port = portpicker::pick_unused_port().expect("No free ports");
    let addr = format!("127.0.0.1:{}", port).parse().unwrap();

    let service = InferadbServiceImpl::new(state.clone());

    let handle = tokio::spawn(async move {
        // Authentication is always required; setup interceptor
        if let Some(cache) = state.jwks_cache {
            let interceptor =
                AuthInterceptor::new(cache, internal_loader, Arc::new(state.config.authentication.clone()));

            Server::builder()
                .add_service(InferadbServiceServer::with_interceptor(service, interceptor))
                .serve(addr)
                .await
                .expect("gRPC server failed");
        } else {
            // No JWKS cache means no auth - server won't start properly
            panic!("JWKS cache is required for authentication");
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    (handle, port)
}

// NOTE: Health endpoint test removed - authentication is always required.
// Health checks should be performed through authenticated channels or via
// dedicated health check endpoints that bypass auth (if configured separately).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grpc_check_without_token() {
    // When auth is enabled, check without token should fail with UNAUTHENTICATED
    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:9999/tenants".to_string(),
            cache,
            Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state(Some(jwks_cache));
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferadbServiceClient::new(channel);

    let req = ProtoEvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let stream = futures::stream::once(async { req });
    let request = Request::new(stream);
    let response = client.evaluate(request).await;

    assert!(response.is_err());
    let err = response.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grpc_check_with_invalid_token() {
    // Invalid JWT should fail with UNAUTHENTICATED
    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:9999/tenants".to_string(),
            cache,
            Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state(Some(jwks_cache));
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferadbServiceClient::new(channel);

    let req = ProtoEvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let stream = futures::stream::once(async { req });
    let mut request = Request::new(stream);

    // Add invalid token to metadata
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("Bearer invalid-jwt-token"));

    let response = client.evaluate(request).await;

    assert!(response.is_err());
    let err = response.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grpc_check_with_tenant_jwt() {
    // Start mock JWKS server
    let mock_jwks = common::MockJwksServer::start().await;

    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(mock_jwks.base_url.clone(), cache, Duration::from_secs(300)).unwrap(),
    );

    let state = create_test_state(Some(jwks_cache));
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferadbServiceClient::new(channel);

    // Generate valid tenant JWT
    let tenant_id = "test-tenant-123";
    let token = mock_jwks.generate_tenant_jwt(tenant_id, &["inferadb.check"], 3600);

    let req = ProtoEvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let stream = futures::stream::once(async { req });
    let mut request = Request::new(stream);

    // Add valid token to metadata
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::try_from(format!("Bearer {}", token)).unwrap());

    let response = client.evaluate(request).await;

    assert!(response.is_ok(), "Expected success with valid tenant JWT");
    let mut resp_stream = response.unwrap().into_inner();
    let check_response = resp_stream.next().await.unwrap().unwrap();

    // Should be DENY because no tuples are written
    assert_eq!(check_response.decision, 2); // Decision::Deny = 2

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grpc_check_with_internal_jwt() {
    // Generate internal keypair
    let keypair = generate_internal_keypair();

    // Create internal JWKS
    let internal_jwks = create_internal_jwks(vec![keypair.public_jwk.clone()]);

    // Save JWKS to temp file
    let temp_dir = tempfile::tempdir().unwrap();
    let jwks_path = temp_dir.path().join("internal_jwks.json");
    std::fs::write(&jwks_path, serde_json::to_string_pretty(&internal_jwks).unwrap()).unwrap();

    // Create internal loader
    let internal_loader = InternalJwksLoader::from_config(Some(&jwks_path), None)
        .expect("Failed to create internal loader");

    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:9999/tenants".to_string(),
            cache,
            Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state(Some(jwks_cache));
    let (server_handle, port) =
        start_grpc_server_with_auth(state, Some(Arc::new(internal_loader))).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferadbServiceClient::new(channel);

    // Generate valid internal JWT
    let claims = InternalClaims::default();
    let token = generate_internal_jwt(&keypair, claims);

    let req = ProtoEvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let stream = futures::stream::once(async { req });
    let mut request = Request::new(stream);

    // Add valid internal token to metadata
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::try_from(format!("Bearer {}", token)).unwrap());

    let response = client.evaluate(request).await;

    if let Err(e) = &response {
        eprintln!("gRPC error: code={:?}, message={}", e.code(), e.message());
    }
    assert!(
        response.is_ok(),
        "Expected success with valid internal JWT, got: {:?}",
        response.as_ref().err()
    );
    let mut resp_stream = response.unwrap().into_inner();
    let check_response = resp_stream.next().await.unwrap().unwrap();

    // Should be DENY because no tuples are written
    assert_eq!(check_response.decision, 2); // Decision::Deny = 2

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grpc_check_with_expired_internal_jwt() {
    // Generate internal keypair
    let keypair = generate_internal_keypair();

    // Create internal JWKS
    let internal_jwks = create_internal_jwks(vec![keypair.public_jwk.clone()]);

    // Save JWKS to temp file
    let temp_dir = tempfile::tempdir().unwrap();
    let jwks_path = temp_dir.path().join("internal_jwks.json");
    std::fs::write(&jwks_path, serde_json::to_string_pretty(&internal_jwks).unwrap()).unwrap();

    // Create internal loader
    let internal_loader = InternalJwksLoader::from_config(Some(&jwks_path), None)
        .expect("Failed to create internal loader");

    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:9999/tenants".to_string(),
            cache,
            Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state(Some(jwks_cache));
    let (server_handle, port) =
        start_grpc_server_with_auth(state, Some(Arc::new(internal_loader))).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferadbServiceClient::new(channel);

    // Generate EXPIRED internal JWT
    let claims = InternalClaims::expired();
    let token = generate_internal_jwt(&keypair, claims);

    let req = ProtoEvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let stream = futures::stream::once(async { req });
    let mut request = Request::new(stream);

    // Add expired token to metadata
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::try_from(format!("Bearer {}", token)).unwrap());

    let response = client.evaluate(request).await;

    assert!(response.is_err());
    let err = response.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(err.message().contains("Token expired"));

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grpc_lowercase_authorization_metadata() {
    // Verify that gRPC metadata normalization works correctly
    // (gRPC normalizes all metadata keys to lowercase)

    let cache = Arc::new(
        moka::future::Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(300))
            .build(),
    );

    let jwks_cache = Arc::new(
        JwksCache::new(
            "http://127.0.0.1:9999/tenants".to_string(),
            cache,
            Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state(Some(jwks_cache));
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferadbServiceClient::new(channel);

    let req = ProtoEvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let stream = futures::stream::once(async { req });
    let mut request = Request::new(stream);

    // Use lowercase "authorization" key
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("Bearer invalid-token"));

    let response = client.evaluate(request).await;

    // Should get UNAUTHENTICATED (not missing metadata)
    assert!(response.is_err());
    let err = response.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    server_handle.abort();
}
