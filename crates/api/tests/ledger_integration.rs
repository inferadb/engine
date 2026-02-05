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
//! cargo test --test ledger_integration
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

    let (state, ledger_vault) = create_ledger_test_state().await;
    eprintln!("[DEBUG] Ledger vault_id (backend scope): {}", ledger_vault);

    // Create organization first
    let org = inferadb_engine_types::Organization {
        id: unique_vault_id(),
        name: "Vault Test Org".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    eprintln!("[DEBUG] Creating org with id: {}", org.id);
    state.store.create_organization(org.clone()).await.unwrap();

    // Create vault
    let vault = inferadb_engine_types::Vault {
        id: unique_vault_id(),
        organization: org.id,
        name: "Test Vault".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    eprintln!("[DEBUG] Creating Engine vault with id: {}, org: {}", vault.id, vault.organization);

    let created = state.store.create_vault(vault.clone()).await.expect("create should succeed");
    eprintln!("[DEBUG] Vault created successfully");

    assert_eq!(created.name, "Test Vault");

    // Get vault
    eprintln!("[DEBUG] Getting vault by id: {}", created.id);
    let retrieved = state.store.get_vault(created.id).await.expect("get should succeed");
    eprintln!("[DEBUG] Get vault result: {:?}", retrieved.as_ref().map(|v| v.id));

    assert!(retrieved.is_some());

    // List vaults for organization
    eprintln!("[DEBUG] Listing vaults for org: {}", org.id);
    let vaults =
        state.store.list_vaults_for_organization(org.id).await.expect("list should succeed");
    eprintln!("[DEBUG] List vaults returned {} items", vaults.len());

    assert!(!vaults.is_empty(), "Expected vaults to be non-empty, org_id={}, vault_id={}", org.id, vault.id);

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
    eprintln!("[DEBUG] Using vault ID: {}", vault);

    // First, write sequentially to verify basic writes work
    eprintln!("[DEBUG] Testing sequential write first...");
    let test_rel = vec![create_test_relationship(vault, "document:seq-test", "viewer", "user:seq-test")];
    match state.store.write(vault, test_rel).await {
        Ok(rev) => eprintln!("[DEBUG] Sequential write succeeded, revision: {:?}", rev),
        Err(e) => eprintln!("[DEBUG] Sequential write FAILED: {:?}", e),
    }

    // Check revision
    let current_rev = state.store.get_revision(vault).await;
    eprintln!("[DEBUG] Current revision after sequential write: {:?}", current_rev);

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
            let result = store.write(v, rel).await;
            eprintln!("[DEBUG] Concurrent write {} result: {:?}", i, result);
            result
        }));
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.expect("task should succeed").expect("write should succeed");
    }

    // Check final revision
    let final_rev = state.store.get_revision(vault).await;
    eprintln!("[DEBUG] Final revision after concurrent writes: {:?}", final_rev);

    // First, try to read back the sequential write directly
    eprintln!("[DEBUG] Trying direct read of sequential write...");
    let key = inferadb_engine_types::RelationshipKey {
        resource: "document:seq-test".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:seq-test".to_string()),
    };
    let direct_read = state.store.read(vault, &key, inferadb_engine_types::Revision::zero()).await;
    eprintln!("[DEBUG] Direct read result: {:?}", direct_read);

    // Try to read one of the concurrent writes
    eprintln!("[DEBUG] Trying direct read of concurrent write 0...");
    let key = inferadb_engine_types::RelationshipKey {
        resource: "document:concurrent-0".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:concurrent-0".to_string()),
    };
    let direct_read2 = state.store.read(vault, &key, inferadb_engine_types::Revision::zero()).await;
    eprintln!("[DEBUG] Direct read concurrent-0 result: {:?}", direct_read2);

    // Debug: Check the key format being used
    let prefix = format!("engine:rel:{}:", vault);
    let end = format!("engine:rel:{}~", vault);
    eprintln!("[DEBUG] Range scan prefix: {:?}", prefix);
    eprintln!("[DEBUG] Range scan end: {:?}", end);

    // Debug: Try list_relationships without any filters to see if that works
    eprintln!("[DEBUG] Trying list_relationships with no filters...");
    let all_results = state
        .store
        .list_relationships(vault, None, None, None, inferadb_engine_types::Revision::zero())
        .await
        .unwrap();
    eprintln!("[DEBUG] list_relationships with no filters returned {} results", all_results.len());

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

    eprintln!("[DEBUG] list_relationships returned {} results", results.len());
    for (i, rel) in results.iter().enumerate() {
        eprintln!("[DEBUG] Result {}: {} {} {}", i, rel.resource, rel.relation, rel.subject);
    }

    assert_eq!(results.len(), 11, "all writes should succeed (1 seq + 10 concurrent)");
}

/// Debug test: directly tests LedgerBackend get_range to isolate the issue
#[tokio::test]
async fn test_ledger_backend_get_range_debug() {
    use inferadb_common_storage::StorageBackend;

    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let vault_id = unique_vault_id();
    eprintln!("[DEBUG] Testing with vault_id: {}", vault_id);

    let backend = create_ledger_backend_with_vault(vault_id).await;

    // Write directly to the backend using a key pattern similar to relationships
    let test_key = format!("engine:rel:{}:document:test:viewer:user:test", vault_id);
    let test_value = b"test-value".to_vec();

    eprintln!("[DEBUG] Writing key: {:?}", test_key);
    eprintln!("[DEBUG] Key hex: {:?}", hex::encode(test_key.as_bytes()));

    backend
        .set(test_key.clone().into_bytes(), test_value.clone())
        .await
        .expect("set should succeed");
    eprintln!("[DEBUG] Write succeeded");

    // Direct read
    eprintln!("[DEBUG] Trying direct get...");
    let read_result = backend.get(test_key.as_bytes()).await.expect("get should succeed");
    eprintln!("[DEBUG] Direct get result: {:?}", read_result.map(|b| String::from_utf8_lossy(&b).to_string()));

    // Range scan with exact prefix
    let prefix = format!("engine:rel:{}:", vault_id);
    let end = format!("engine:rel:{}~", vault_id);
    eprintln!("[DEBUG] Range scan start: {:?}", prefix);
    eprintln!("[DEBUG] Range scan start hex: {:?}", hex::encode(prefix.as_bytes()));
    eprintln!("[DEBUG] Range scan end: {:?}", end);
    eprintln!("[DEBUG] Range scan end hex: {:?}", hex::encode(end.as_bytes()));

    // Check if the test key should be in range
    let key_hex = hex::encode(test_key.as_bytes());
    let start_hex = hex::encode(prefix.as_bytes());
    let end_hex = hex::encode(end.as_bytes());
    eprintln!("[DEBUG] Key hex starts with prefix: {}", key_hex.starts_with(&start_hex[..start_hex.len() - 2]));
    eprintln!("[DEBUG] Key hex >= start: {}", key_hex >= start_hex);
    eprintln!("[DEBUG] Key hex < end: {}", key_hex < end_hex);

    let range_result = backend
        .get_range(prefix.clone().into_bytes()..end.clone().into_bytes())
        .await
        .expect("get_range should succeed");

    eprintln!("[DEBUG] get_range returned {} items", range_result.len());
    for (i, kv) in range_result.iter().enumerate() {
        eprintln!(
            "[DEBUG] Item {}: key={:?} value={:?}",
            i,
            String::from_utf8_lossy(&kv.key),
            String::from_utf8_lossy(&kv.value)
        );
    }

    assert!(!range_result.is_empty(), "range scan should find the written key");
}

/// Debug test: tests the full write -> list_relationships path through EngineStorage
#[tokio::test]
async fn test_engine_storage_list_relationships_debug() {
    use inferadb_common_storage::StorageBackend;

    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let vault_id = unique_vault_id();
    eprintln!("[DEBUG-ES] Testing with vault_id: {}", vault_id);

    let backend = create_ledger_backend_with_vault(vault_id).await;
    let store = EngineStorage::builder().backend(backend.clone()).build();

    // Check initial revision
    let initial_rev = store.get_revision(vault_id).await;
    eprintln!("[DEBUG-ES] Initial revision: {:?}", initial_rev);

    // Write a relationship through EngineStorage
    let rel = create_test_relationship(vault_id, "document:test", "viewer", "user:alice");
    eprintln!("[DEBUG-ES] Writing relationship: {:?}", rel);

    let write_rev = store.write_relationships(vault_id, vec![rel]).await.expect("write should succeed");
    eprintln!("[DEBUG-ES] Write returned revision: {:?}", write_rev);

    // Check revision after write
    let after_write_rev = store.get_revision(vault_id).await;
    eprintln!("[DEBUG-ES] Revision after write: {:?}", after_write_rev);

    // Try direct read through InferaStore
    let key = inferadb_engine_types::RelationshipKey {
        resource: "document:test".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let direct_read = store.read_relationships(vault_id, &key, inferadb_engine_types::Revision::zero()).await;
    eprintln!("[DEBUG-ES] Direct read result: {:?}", direct_read);

    // Now try list_relationships
    let list_result = store
        .list_relationships(vault_id, None, None, None, inferadb_engine_types::Revision::zero())
        .await;
    eprintln!("[DEBUG-ES] list_relationships result: {:?}", list_result);

    // Also check the raw storage key used
    let storage_key = format!("engine:rel:{}:document:test:viewer:user:alice", vault_id);
    eprintln!("[DEBUG-ES] Expected storage key: {:?}", storage_key);

    // Read the raw value from the backend
    let raw_value = backend.get(storage_key.as_bytes()).await;
    eprintln!("[DEBUG-ES] Raw backend get result: {:?}", raw_value);
    if let Ok(Some(data)) = raw_value {
        eprintln!("[DEBUG-ES] Raw value: {:?}", String::from_utf8_lossy(&data));
    }

    // Check what the range scan sees
    let prefix = format!("engine:rel:{}:", vault_id);
    let end = format!("engine:rel:{}~", vault_id);
    let range_result = backend.get_range(prefix.into_bytes()..end.into_bytes()).await;
    eprintln!("[DEBUG-ES] Backend get_range result: {:?}", range_result);

    let results = list_result.expect("list should succeed");
    assert_eq!(results.len(), 1, "should find the written relationship");
}

/// Debug test: tests if two independent backends can see each other's data via get_range
#[tokio::test]
async fn test_independent_backends_get_range_debug() {
    use inferadb_common_storage::StorageBackend;

    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let vault_id = unique_vault_id();
    eprintln!("[DEBUG-IB] Testing with vault_id: {}", vault_id);
    eprintln!("[DEBUG-IB] Backend vault_id (Ledger-level): {}", vault_id);

    // Create two INDEPENDENT backends with the same vault_id
    let backend_writer = create_ledger_backend_with_vault(vault_id).await;
    let backend_reader = create_ledger_backend_with_vault(vault_id).await;

    eprintln!("[DEBUG-IB] Created two independent backends");
    eprintln!("[DEBUG-IB] Writer vault_id: {:?}", backend_writer.vault_id());
    eprintln!("[DEBUG-IB] Reader vault_id: {:?}", backend_reader.vault_id());

    // Write using backend_writer
    let test_key = format!("engine:rel:{}:document:test:viewer:user:test", vault_id);
    let test_value = b"test-value-independent".to_vec();

    eprintln!("[DEBUG-IB] Writing key: {:?}", test_key);
    backend_writer
        .set(test_key.clone().into_bytes(), test_value.clone())
        .await
        .expect("write should succeed");
    eprintln!("[DEBUG-IB] Write succeeded");

    // Direct read from backend_reader
    eprintln!("[DEBUG-IB] Direct get from reader backend...");
    let read_result = backend_reader.get(test_key.as_bytes()).await.expect("get should succeed");
    eprintln!("[DEBUG-IB] Direct get result: {:?}", read_result.map(|b| String::from_utf8_lossy(&b).to_string()));

    // Range scan from backend_reader
    let prefix = format!("engine:rel:{}:", vault_id);
    let end = format!("engine:rel:{}~", vault_id);
    eprintln!("[DEBUG-IB] Range scan from reader backend...");
    eprintln!("[DEBUG-IB] Prefix: {:?}", prefix);
    eprintln!("[DEBUG-IB] End: {:?}", end);

    let range_result = backend_reader
        .get_range(prefix.clone().into_bytes()..end.clone().into_bytes())
        .await
        .expect("get_range should succeed");

    eprintln!("[DEBUG-IB] get_range from reader returned {} items", range_result.len());
    for (i, kv) in range_result.iter().enumerate() {
        eprintln!(
            "[DEBUG-IB] Item {}: key={:?} value={:?}",
            i,
            String::from_utf8_lossy(&kv.key),
            String::from_utf8_lossy(&kv.value)
        );
    }

    // Also try range scan from the writer backend
    eprintln!("[DEBUG-IB] Range scan from writer backend...");
    let range_result_writer = backend_writer
        .get_range(prefix.into_bytes()..end.into_bytes())
        .await
        .expect("get_range should succeed");

    eprintln!("[DEBUG-IB] get_range from writer returned {} items", range_result_writer.len());
    for (i, kv) in range_result_writer.iter().enumerate() {
        eprintln!(
            "[DEBUG-IB] Writer Item {}: key={:?} value={:?}",
            i,
            String::from_utf8_lossy(&kv.key),
            String::from_utf8_lossy(&kv.value)
        );
    }

    assert!(!range_result.is_empty(), "range scan from reader should find data");
}

/// Debug test: directly tests the SDK's list_entities with various prefix configurations
#[tokio::test]
async fn test_sdk_list_entities_debug() {
    use inferadb_common_storage::StorageBackend;
    use inferadb_ledger_sdk::ListEntitiesOpts;

    if !should_run() {
        eprintln!("Skipping Ledger integration test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let vault_id = unique_vault_id();
    let namespace_id = ledger_namespace_id();
    eprintln!("[DEBUG-SDK] Testing with namespace_id: {}, vault_id: {}", namespace_id, vault_id);

    let backend = create_ledger_backend_with_vault(vault_id).await;

    // Write a test key
    let test_key = format!("engine:rel:{}:document:test:viewer:user:alice", vault_id);
    let test_key_hex = hex::encode(test_key.as_bytes());
    eprintln!("[DEBUG-SDK] Writing key: {:?}", test_key);
    eprintln!("[DEBUG-SDK] Key hex: {:?}", test_key_hex);

    backend
        .set(test_key.clone().into_bytes(), b"test-value".to_vec())
        .await
        .expect("write should succeed");
    eprintln!("[DEBUG-SDK] Write succeeded");

    // Direct read to confirm
    let read_result = backend.get(test_key.as_bytes()).await.expect("get should succeed");
    eprintln!("[DEBUG-SDK] Direct get result: {:?}", read_result.is_some());

    // Now call list_entities directly through the SDK
    let client = backend.client();

    // Test 1: Empty prefix (should return all entities in vault)
    eprintln!("[DEBUG-SDK] Test 1: list_entities with empty prefix");
    let opts1 = ListEntitiesOpts::builder()
        .key_prefix("")
        .vault_id(vault_id)
        .limit(100)
        .build();
    let result1 = client.list_entities(namespace_id, opts1).await.expect("list_entities should succeed");
    eprintln!("[DEBUG-SDK] Empty prefix returned {} items", result1.items.len());
    for (i, entity) in result1.items.iter().take(5).enumerate() {
        eprintln!("[DEBUG-SDK]   Item {}: key={}", i, entity.key);
    }

    // Test 2: The exact hex prefix we compute
    let prefix_raw = format!("engine:rel:{}:", vault_id);
    let end_raw = format!("engine:rel:{}~", vault_id);
    let prefix_hex = hex::encode(prefix_raw.as_bytes());
    let end_hex = hex::encode(end_raw.as_bytes());
    let common_prefix = prefix_hex.chars()
        .zip(end_hex.chars())
        .take_while(|(a, b)| a == b)
        .map(|(c, _)| c)
        .collect::<String>();

    eprintln!("[DEBUG-SDK] Test 2: list_entities with computed common prefix");
    eprintln!("[DEBUG-SDK] Prefix raw: {:?}", prefix_raw);
    eprintln!("[DEBUG-SDK] Prefix hex: {:?}", prefix_hex);
    eprintln!("[DEBUG-SDK] End hex: {:?}", end_hex);
    eprintln!("[DEBUG-SDK] Common prefix: {:?} (len={})", common_prefix, common_prefix.len());

    let opts2 = ListEntitiesOpts::builder()
        .key_prefix(&common_prefix)
        .vault_id(vault_id)
        .limit(100)
        .build();
    let result2 = client.list_entities(namespace_id, opts2).await.expect("list_entities should succeed");
    eprintln!("[DEBUG-SDK] Common prefix returned {} items", result2.items.len());
    for (i, entity) in result2.items.iter().take(5).enumerate() {
        eprintln!("[DEBUG-SDK]   Item {}: key={}", i, entity.key);
    }

    // Test 3: Full key as prefix
    eprintln!("[DEBUG-SDK] Test 3: list_entities with full key as prefix");
    let opts3 = ListEntitiesOpts::builder()
        .key_prefix(&test_key_hex)
        .vault_id(vault_id)
        .limit(100)
        .build();
    let result3 = client.list_entities(namespace_id, opts3).await.expect("list_entities should succeed");
    eprintln!("[DEBUG-SDK] Full key prefix returned {} items", result3.items.len());

    // Check if the entity key matches
    eprintln!("[DEBUG-SDK] Expected key hex: {:?}", test_key_hex);
    if !result1.items.is_empty() {
        eprintln!("[DEBUG-SDK] First entity key: {:?}", result1.items[0].key);
        eprintln!("[DEBUG-SDK] Keys match: {}", result1.items[0].key == test_key_hex);
    }

    assert!(!result1.items.is_empty(), "empty prefix should return entities");
}
