//! Integration tests for Engine with a real Ledger backend.
//!
//! These tests require a running Ledger server. They are skipped unless the
//! `RUN_LEDGER_INTEGRATION_TESTS` environment variable is set.
//!
//! # Running the tests
//!
//! Using Docker Compose:
//! ```bash
//! cd docker/ledger-integration-tests && ./run-tests.sh
//! ```
//!
//! Or manually:
//! ```bash
//! # Start Ledger server
//! INFERADB__LEDGER__BOOTSTRAP_EXPECT=1 ledger
//!
//! # Run tests
//! RUN_LEDGER_INTEGRATION_TESTS=1 \
//! LEDGER_ENDPOINT=http://localhost:50051 \
//! cargo test --test ledger_integration -- --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    env,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicI64, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
};
use inferadb_common_storage_ledger::{
    ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
};
use inferadb_engine_api::AppState;
use inferadb_engine_config::Config;
use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use inferadb_engine_repository::EngineStorage;
use inferadb_engine_store::InferaStore;
use inferadb_engine_types::{AuthContext, AuthMethod, Relationship};
use tower::ServiceExt;

/// Test ID counter initialized with PID-based offset to avoid collisions when
/// nextest runs tests in parallel processes. Each process gets a unique 10,000-ID
/// range based on its PID modulo 1000.
static TEST_ID_COUNTER: LazyLock<AtomicI64> = LazyLock::new(|| {
    let pid = std::process::id() as i64;
    AtomicI64::new(20000000000000 + (pid % 1000) * 10000)
});

fn generate_test_id() -> i64 {
    TEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// ============================================================================
// Test Configuration
// ============================================================================

fn should_run() -> bool {
    env::var("RUN_LEDGER_INTEGRATION_TESTS").is_ok()
}

fn ledger_endpoint() -> String {
    env::var("LEDGER_ENDPOINT").unwrap_or_else(|_| "http://localhost:50051".to_string())
}

fn ledger_namespace_id() -> i64 {
    env::var("LEDGER_NAMESPACE_ID").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

fn unique_vault_id() -> i64 {
    generate_test_id()
}

// ============================================================================
// Test Infrastructure
// ============================================================================

fn create_test_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        TypeDef {
            name: "document".to_string(),
            relations: vec![
                RelationDef { name: "owner".to_string(), expr: Some(RelationExpr::This) },
                RelationDef { name: "viewer".to_string(), expr: Some(RelationExpr::This) },
                RelationDef { name: "editor".to_string(), expr: Some(RelationExpr::This) },
            ],
            forbids: vec![],
        },
        TypeDef {
            name: "folder".to_string(),
            relations: vec![
                RelationDef { name: "owner".to_string(), expr: Some(RelationExpr::This) },
                RelationDef { name: "viewer".to_string(), expr: Some(RelationExpr::This) },
            ],
            forbids: vec![],
        },
    ]))
}

fn create_test_config() -> Config {
    let mut config = Config::default();
    config.cache.enabled = true;
    config.cache.capacity = 1000;
    config.cache.ttl = 300;
    config
}

async fn create_ledger_backend_with_vault(vault_id: i64) -> LedgerBackend {
    let client_config = ClientConfig::builder()
        .servers(ServerSource::from_static([ledger_endpoint()]))
        .client_id(format!("engine-test-{}", vault_id))
        .build()
        .expect("valid client config");
    let config = LedgerBackendConfig::builder()
        .client(client_config)
        .namespace_id(ledger_namespace_id())
        .vault_id(vault_id)
        .build();

    LedgerBackend::new(config).await.expect("backend creation should succeed")
}

/// Creates test state and returns (state, vault_id) so tests use the same vault
/// the backend was configured with.
async fn create_ledger_test_state() -> (AppState, i64) {
    let vault_id = unique_vault_id();
    let backend = create_ledger_backend_with_vault(vault_id).await;
    let store: Arc<dyn InferaStore> = Arc::new(EngineStorage::builder().backend(backend).build());
    let schema = create_test_schema();
    let config = create_test_config();

    let state = AppState::builder().store(store).schema(schema).config(Arc::new(config)).build();
    (state, vault_id)
}

fn create_test_auth(vault: i64, organization: i64) -> AuthContext {
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

async fn test_auth_middleware(
    auth_context: AuthContext,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    request.extensions_mut().insert(Arc::new(auth_context));
    next.run(request).await
}

fn with_test_auth(router: Router, vault: i64, organization: i64) -> Router {
    let auth = create_test_auth(vault, organization);
    router.layer(middleware::from_fn(move |req, next| {
        let auth_clone = auth.clone();
        async move { test_auth_middleware(auth_clone, req, next).await }
    }))
}

fn create_test_relationship(
    vault: i64,
    resource: &str,
    relation: &str,
    subject: &str,
) -> Relationship {
    Relationship {
        vault,
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: subject.to_string(),
    }
}

// ============================================================================
// Basic Operations Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_engine_write_and_read_relationships() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, vault) = create_ledger_test_state().await;

    // Write relationships
    let relationships = vec![
        create_test_relationship(vault, "document:readme", "viewer", "user:alice"),
        create_test_relationship(vault, "document:readme", "editor", "user:bob"),
    ];

    let revision = state.store.write(vault, relationships).await.expect("write should succeed");

    assert!(revision.0 > 0, "revision should be positive");

    // Read back
    let key = inferadb_engine_types::RelationshipKey {
        resource: "document:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results = state
        .store
        .read(vault, &key, inferadb_engine_types::Revision::zero())
        .await
        .expect("read should succeed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].subject, "user:alice");
}

#[tokio::test]
async fn test_ledger_engine_delete_relationships() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, vault) = create_ledger_test_state().await;

    // Write
    let relationships =
        vec![create_test_relationship(vault, "document:secret", "viewer", "user:charlie")];
    state.store.write(vault, relationships).await.unwrap();

    // Delete
    let key = inferadb_engine_types::RelationshipKey {
        resource: "document:secret".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:charlie".to_string()),
    };
    state.store.delete(vault, &key).await.unwrap();

    // Verify deleted
    let results =
        state.store.read(vault, &key, inferadb_engine_types::Revision::zero()).await.unwrap();

    assert!(results.is_empty(), "relationship should be deleted");
}

#[tokio::test]
async fn test_ledger_engine_vault_isolation() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    // Vault isolation requires separate backends since LedgerBackend is scoped to one vault
    let vault_a = unique_vault_id();
    let vault_b = unique_vault_id();

    let backend_a = create_ledger_backend_with_vault(vault_a).await;
    let backend_b = create_ledger_backend_with_vault(vault_b).await;

    let store_a: Arc<dyn InferaStore> =
        Arc::new(EngineStorage::builder().backend(backend_a).build());
    let store_b: Arc<dyn InferaStore> =
        Arc::new(EngineStorage::builder().backend(backend_b).build());

    // Write to vault A
    let rel_a = vec![create_test_relationship(vault_a, "document:shared", "viewer", "user:alice")];
    store_a.write(vault_a, rel_a).await.unwrap();

    // Write to vault B
    let rel_b = vec![create_test_relationship(vault_b, "document:shared", "viewer", "user:bob")];
    store_b.write(vault_b, rel_b).await.unwrap();

    // Verify isolation - each store only sees its own data
    let key = inferadb_engine_types::RelationshipKey {
        resource: "document:shared".to_string(),
        relation: "viewer".to_string(),
        subject: None,
    };

    let results_a =
        store_a.read(vault_a, &key, inferadb_engine_types::Revision::zero()).await.unwrap();
    let results_b =
        store_b.read(vault_b, &key, inferadb_engine_types::Revision::zero()).await.unwrap();

    assert_eq!(results_a.len(), 1);
    assert_eq!(results_a[0].subject, "user:alice");
    assert_eq!(results_b.len(), 1);
    assert_eq!(results_b[0].subject, "user:bob");
}

// ============================================================================
// API Integration Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_engine_api_write_endpoint() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, vault) = create_ledger_test_state().await;
    let organization = unique_vault_id();

    let router = inferadb_engine_api::create_test_router(state)
        .await
        .expect("router creation should succeed");
    let router = with_test_auth(router, vault, organization);

    // Write via API
    let body = serde_json::json!({
        "relationships": [
            {
                "resource": "document:api-test",
                "relation": "viewer",
                "subject": "user:api-user"
            }
        ]
    });

    let request = Request::builder()
        .method("POST")
        .uri("/access/v1/relationships/write")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_ledger_engine_api_check_endpoint() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, vault) = create_ledger_test_state().await;
    let organization = unique_vault_id();

    // Pre-populate
    let relationships =
        vec![create_test_relationship(vault, "document:check-test", "viewer", "user:checker")];
    state.store.write(vault, relationships).await.unwrap();

    let router = inferadb_engine_api::create_test_router(state)
        .await
        .expect("router creation should succeed");
    let router = with_test_auth(router, vault, organization);

    // Check via API (using AuthZEN evaluation endpoint)
    let body = serde_json::json!({
        "subject": {"type": "user", "id": "checker"},
        "action": {"name": "viewer"},
        "resource": {"type": "document", "id": "check-test"}
    });

    let request = Request::builder()
        .method("POST")
        .uri("/access/v1/evaluation")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(result["decision"], true);
}

// ============================================================================
// Change Log Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_engine_change_log() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, vault) = create_ledger_test_state().await;

    // Write some relationships
    for i in 0..5 {
        let relationships = vec![create_test_relationship(
            vault,
            &format!("document:log-test-{}", i),
            "viewer",
            &format!("user:log-user-{}", i),
        )];
        state.store.write(vault, relationships).await.unwrap();
    }

    // Read change log
    let changes = state
        .store
        .read_changes(vault, inferadb_engine_types::Revision::zero(), &[], Some(10))
        .await
        .unwrap();

    assert!(!changes.is_empty(), "should have change log entries");
}

// ============================================================================
// Organization and Vault CRUD Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_engine_organization_crud() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, _vault) = create_ledger_test_state().await;

    // Create organization
    let org = inferadb_engine_types::Organization {
        id: unique_vault_id(),
        name: "Test Org".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let created =
        state.store.create_organization(org.clone()).await.expect("create should succeed");

    assert_eq!(created.name, "Test Org");

    // Get organization
    let retrieved = state.store.get_organization(created.id).await.expect("get should succeed");

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "Test Org");

    // Delete organization
    state.store.delete_organization(created.id).await.expect("delete should succeed");

    // Verify deleted
    let deleted = state.store.get_organization(created.id).await.unwrap();
    assert!(deleted.is_none());
}

#[tokio::test]
async fn test_ledger_engine_vault_crud() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, _vault) = create_ledger_test_state().await;

    // Create organization first
    let org = inferadb_engine_types::Organization {
        id: unique_vault_id(),
        name: "Vault Test Org".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    state.store.create_organization(org.clone()).await.unwrap();

    // Create vault
    let vault = inferadb_engine_types::Vault {
        id: unique_vault_id(),
        organization: org.id,
        name: "Test Vault".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let created = state.store.create_vault(vault.clone()).await.expect("create should succeed");

    assert_eq!(created.name, "Test Vault");

    // Get vault
    let retrieved = state.store.get_vault(created.id).await.expect("get should succeed");

    assert!(retrieved.is_some());

    // List vaults for organization
    let vaults =
        state.store.list_vaults_for_organization(org.id).await.expect("list should succeed");

    assert!(!vaults.is_empty());

    // Clean up
    state.store.delete_vault(created.id).await.unwrap();
    state.store.delete_organization(org.id).await.unwrap();
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_engine_concurrent_writes() {
    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let (state, vault) = create_ledger_test_state().await;

    // Spawn concurrent writers
    let mut handles = Vec::new();
    for i in 0..10 {
        let store = state.store.clone();
        let v = vault;
        handles.push(tokio::spawn(async move {
            let rel = vec![create_test_relationship(
                v,
                &format!("document:concurrent-{}", i),
                "viewer",
                &format!("user:concurrent-{}", i),
            )];
            store.write(v, rel).await
        }));
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.expect("task should succeed").expect("write should succeed");
    }

    // Verify all were written
    let results = state
        .store
        .list_relationships(
            vault,
            None,           // resource
            Some("viewer"), // relation
            None,           // subject
            inferadb_engine_types::Revision::zero(),
        )
        .await
        .unwrap();

    assert_eq!(results.len(), 10, "all concurrent writes should succeed");
}
