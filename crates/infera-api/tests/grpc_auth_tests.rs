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
use infera_api::{
    AppState,
    grpc::proto::{
        EvaluateRequest as ProtoEvaluateRequest, HealthRequest,
        infera_service_client::InferaServiceClient,
    },
};
use infera_auth::{internal::InternalJwksLoader, jwks_cache::JwksCache};
use infera_config::Config;
use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use infera_store::MemoryBackend;
// Re-use test helpers from test fixtures
use infera_test_fixtures::{
    InternalClaims, create_internal_jwks, generate_internal_jwt, generate_internal_keypair,
};
use tonic::{
    Code, Request,
    metadata::MetadataValue,
    transport::{Channel, Server},
};

mod common {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use serde_json::json;
    use tokio::sync::RwLock;
    use warp::Filter;

    /// Mock JWKS server for tenant JWT testing
    pub struct MockJwksServer {
        pub keypair: SigningKey,
        pub kid: String,
        pub server: tokio::task::JoinHandle<()>,
        pub port: u16,
    }

    impl MockJwksServer {
        pub async fn start() -> Self {
            let keypair = SigningKey::generate(&mut OsRng);
            let kid = "test-key-grpc-001".to_string();

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

            // Start mock JWKS server on random port
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

            // Bind to random port
            let port = portpicker::pick_unused_port().expect("No free ports");
            let addr = ([127, 0, 0, 1], port);

            let server = tokio::spawn(async move {
                warp::serve(jwks_filter).run(addr).await;
            });

            // Give server time to start
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            Self { keypair, kid, server, port }
        }

        pub fn generate_tenant_jwt(
            &self,
            org_id: &str,
            scopes: &[&str],
            expires_in_secs: i64,
        ) -> String {
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

            // Create PKCS#8 DER encoding for Ed25519
            let private_bytes = self.keypair.to_bytes();
            let mut pkcs8_der = vec![
                0x30, 0x2e, // SEQUENCE, 46 bytes
                0x02, 0x01, 0x00, // INTEGER version 0
                0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
                0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
                0x04, 0x22, // OCTET STRING, 34 bytes
                0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
            ];
            pkcs8_der.extend_from_slice(&private_bytes);

            let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);

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

fn create_test_state(jwks_cache: Option<Arc<JwksCache>>, auth_enabled: bool) -> AppState {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();

    let mut config = Config::default();
    config.auth.enabled = auth_enabled;

    let state = AppState::new(
        store,
        schema,
        None, // No WASM host for tests
        Arc::new(config),
        jwks_cache,
        0i64,
        0i64,
        None, // No server identity for tests
    );

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
    use infera_api::{
        grpc::{InferaServiceImpl, proto::infera_service_server::InferaServiceServer},
        grpc_interceptor::AuthInterceptor,
    };

    let port = portpicker::pick_unused_port().expect("No free ports");
    let addr = format!("127.0.0.1:{}", port).parse().unwrap();

    let service = InferaServiceImpl::new(state.clone());

    let handle = tokio::spawn(async move {
        if state.config.auth.enabled {
            if let Some(cache) = state.jwks_cache {
                let interceptor = AuthInterceptor::new(
                    cache,
                    internal_loader,
                    Arc::new(state.config.auth.clone()),
                );

                Server::builder()
                    .add_service(InferaServiceServer::with_interceptor(service, interceptor))
                    .serve(addr)
                    .await
                    .expect("gRPC server failed");
            }
        } else {
            Server::builder()
                .add_service(InferaServiceServer::new(service))
                .serve(addr)
                .await
                .expect("gRPC server failed");
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    (handle, port)
}

#[tokio::test]
async fn test_grpc_health_unauthenticated() {
    // Health endpoint should work without authentication
    let state = create_test_state(None, false);
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferaServiceClient::new(channel);

    let request = Request::new(HealthRequest {});
    let response = client.health(request).await;

    assert!(response.is_ok());
    let health = response.unwrap().into_inner();
    assert_eq!(health.status, "healthy");
    assert_eq!(health.service, "inferadb");

    server_handle.abort();
}

#[tokio::test]
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

    let state = create_test_state(Some(jwks_cache), true);
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferaServiceClient::new(channel);

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

#[tokio::test]
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

    let state = create_test_state(Some(jwks_cache), true);
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferaServiceClient::new(channel);

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

#[tokio::test]
#[ignore] // TODO: Mock JWKS server needs optimization - test hangs during JWKS fetch
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
        JwksCache::new(
            format!("http://127.0.0.1:{}/tenants", mock_jwks.port),
            cache,
            Duration::from_secs(300),
        )
        .unwrap(),
    );

    let state = create_test_state(Some(jwks_cache), true);
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferaServiceClient::new(channel);

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

#[tokio::test]
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

    let state = create_test_state(Some(jwks_cache), true);
    let (server_handle, port) =
        start_grpc_server_with_auth(state, Some(Arc::new(internal_loader))).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferaServiceClient::new(channel);

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

#[tokio::test]
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

    let state = create_test_state(Some(jwks_cache), true);
    let (server_handle, port) =
        start_grpc_server_with_auth(state, Some(Arc::new(internal_loader))).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferaServiceClient::new(channel);

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

#[tokio::test]
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

    let state = create_test_state(Some(jwks_cache), true);
    let (server_handle, port) = start_grpc_server_with_auth(state, None).await;

    let channel = Channel::from_shared(format!("http://127.0.0.1:{}", port))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = InferaServiceClient::new(channel);

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
