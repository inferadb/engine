//! Integration Test Framework
//!
//! This module provides common test utilities for integration tests:
//! - In-memory backend setup
//! - Test configuration
//! - Mock authentication via test middleware
//! - Test state builders
//!
//! ## Authentication in Tests
//!
//! Since authentication is always enabled in production, tests use a special
//! test middleware layer that injects a test `AuthContext` into requests.
//! This allows tests to exercise the production code paths while simulating
//! authenticated requests.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use axum::{
    Router,
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use inferadb_engine_api::AppState;
use inferadb_engine_config::Config;
use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use inferadb_engine_repository::EngineStorage;
use inferadb_engine_types::{AuthContext, AuthMethod, Relationship};
use inferadb_storage::MemoryBackend;

static TEST_ID_COUNTER: AtomicI64 = AtomicI64::new(10000000000000);

fn generate_test_id() -> i64 {
    TEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Standard test schema with document type
pub fn create_test_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![TypeDef {
        name: "document".to_string(),
        relations: vec![
            RelationDef { name: "owner".to_string(), expr: Some(RelationExpr::This) },
            RelationDef { name: "viewer".to_string(), expr: Some(RelationExpr::This) },
            RelationDef { name: "editor".to_string(), expr: Some(RelationExpr::This) },
        ],
        forbids: vec![],
    }]))
}

/// Create test configuration
///
/// Note: Authentication is always enabled. Tests use test middleware
/// to inject authenticated contexts.
pub fn create_test_config() -> Config {
    let mut config = Config::default();
    config.cache.enabled = true;
    config.cache.capacity = 1000;
    config.cache.ttl = 300;
    config
}

/// Create test configuration with rate limiting enabled
pub fn create_test_config_with_rate_limiting() -> Config {
    create_test_config()
}

// ============================================================================
// Test Authentication Middleware
// ============================================================================

/// Default test auth context with admin scopes
///
/// Creates an AuthContext suitable for most integration tests with full permissions.
pub fn create_default_test_auth(vault: i64, organization: i64) -> AuthContext {
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
///
/// This middleware bypasses JWT validation and directly injects a test
/// AuthContext, allowing integration tests to exercise the production
/// code paths with simulated authentication.
#[allow(dead_code)]
pub async fn test_auth_middleware(
    auth_context: AuthContext,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    request.extensions_mut().insert(Arc::new(auth_context));
    next.run(request).await
}

/// Apply test authentication middleware to a router
///
/// Wraps the router with a middleware layer that injects test authentication
/// for all requests. Use this to test protected endpoints without actual JWT validation.
///
/// # Example
///
/// ```ignore
/// let router = inferadb_engine_api::create_test_router(state).await?;
/// let authenticated_router = with_test_auth(router, vault_id, organization_id);
/// ```
#[allow(dead_code)]
pub fn with_test_auth(router: Router, vault: i64, organization: i64) -> Router {
    let auth = create_default_test_auth(vault, organization);
    router.layer(middleware::from_fn(move |req, next| {
        let auth_clone = auth.clone();
        async move { test_auth_middleware(auth_clone, req, next).await }
    }))
}

/// Apply test authentication middleware with custom auth context
///
/// Similar to `with_test_auth` but allows specifying a custom AuthContext
/// for testing specific permission scenarios.
#[allow(dead_code)]
pub fn with_custom_test_auth(router: Router, auth_context: AuthContext) -> Router {
    router.layer(middleware::from_fn(move |req, next| {
        let auth_clone = auth_context.clone();
        async move { test_auth_middleware(auth_clone, req, next).await }
    }))
}

/// Create test AppState with default configuration
pub fn create_test_state() -> AppState {
    create_test_state_with_config(create_test_config())
}

/// Create test AppState with custom configuration
pub fn create_test_state_with_config(config: Config) -> AppState {
    let store: Arc<dyn inferadb_engine_store::InferaStore> =
        Arc::new(EngineStorage::new(MemoryBackend::new()));
    let schema = create_test_schema();

    AppState::builder(store, schema, Arc::new(config))
        .wasm_host(None)
        .signing_key_cache(None)
        .build()
}

/// Create test AppState with multiple vaults for multi-tenancy testing
///
/// Returns the AppState and IDs for two vaults with their organizations.
/// Use `with_test_auth` to authenticate requests to specific vaults.
pub fn create_multi_vault_test_state() -> (AppState, i64, i64, i64, i64) {
    let store: Arc<dyn inferadb_engine_store::InferaStore> =
        Arc::new(EngineStorage::new(MemoryBackend::new()));
    let schema = create_test_schema();

    let vault_a = generate_test_id();
    let organization_a = generate_test_id();
    let vault_b = generate_test_id();
    let organization_b = generate_test_id();

    let config = create_test_config();

    let state = AppState::builder(store, schema, Arc::new(config))
        .wasm_host(None)
        .signing_key_cache(None)
        .build();

    (state, vault_a, organization_a, vault_b, organization_b)
}

/// Create mock AuthContext for testing
pub fn create_mock_auth_context(vault: i64, organization: i64, scopes: Vec<String>) -> AuthContext {
    AuthContext {
        client_id: "test_client".to_string(),
        key_id: "test_key".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes,
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        jti: Some("test_jti".to_string()),
        vault,
        organization,
    }
}

/// Create mock admin AuthContext
pub fn create_admin_auth_context(vault: i64, organization: i64) -> AuthContext {
    create_mock_auth_context(vault, organization, vec!["inferadb.admin".to_string()])
}

/// Helper to create test relationship
pub fn create_test_relationship(
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

/// Helper to write relationships to store
pub async fn write_test_relationships(
    state: &AppState,
    vault: i64,
    relationships: Vec<Relationship>,
) -> Result<inferadb_engine_types::Revision, Box<dyn std::error::Error>> {
    let revision = state.store.write(vault, relationships).await?;
    Ok(revision)
}

// Note: Direct evaluation helpers can be added as needed.
// The evaluator provides list_relationships, list_subjects, list_resources methods.
// For evaluation, use the API endpoints or core evaluation logic directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_schema() {
        let schema = create_test_schema();
        assert_eq!(schema.types.len(), 1);
        assert_eq!(schema.types[0].name, "document");
        assert_eq!(schema.types[0].relations.len(), 3);
    }

    #[test]
    fn test_create_test_config() {
        let config = create_test_config();
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_create_test_config_with_rate_limiting() {
        let _config = create_test_config_with_rate_limiting();
    }

    #[tokio::test]
    async fn test_create_test_state() {
        let _state = create_test_state();
        // Test state is created successfully
    }

    #[test]
    fn test_create_default_test_auth() {
        let vault = 11111111111111i64;
        let organization = 22222222222222i64;
        let auth = create_default_test_auth(vault, organization);

        assert_eq!(auth.vault, vault);
        assert_eq!(auth.organization, organization);
        assert!(auth.scopes.contains(&"inferadb.admin".to_string()));
        assert!(auth.scopes.contains(&"inferadb.check".to_string()));
    }

    #[tokio::test]
    async fn test_create_multi_vault_test_state() {
        let (_state, vault_a, organization_a, vault_b, organization_b) =
            create_multi_vault_test_state();
        assert_ne!(vault_a, vault_b);
        assert_ne!(organization_a, organization_b);
    }

    #[test]
    fn test_create_mock_auth_context() {
        let vault = 11111111111111i64;
        let organization = 22222222222222i64;
        let scopes = vec!["inferadb.check".to_string()];

        let auth = create_mock_auth_context(vault, organization, scopes.clone());

        assert_eq!(auth.vault, vault);
        assert_eq!(auth.organization, organization);
        assert_eq!(auth.scopes, scopes);
        assert_eq!(auth.auth_method, AuthMethod::PrivateKeyJwt);
    }

    #[test]
    fn test_create_admin_auth_context() {
        let vault = 11111111111111i64;
        let organization = 22222222222222i64;

        let auth = create_admin_auth_context(vault, organization);

        assert_eq!(auth.vault, vault);
        assert_eq!(auth.organization, organization);
        assert!(auth.scopes.contains(&"inferadb.admin".to_string()));
    }

    #[test]
    fn test_create_test_relationship() {
        let vault = 11111111111111i64;
        let rel = create_test_relationship(vault, "doc:readme", "viewer", "user:alice");

        assert_eq!(rel.vault, vault);
        assert_eq!(rel.resource, "doc:readme");
        assert_eq!(rel.relation, "viewer");
        assert_eq!(rel.subject, "user:alice");
    }

    #[tokio::test]
    async fn test_write_test_relationships() {
        let state = create_test_state();
        let vault = 11111111111111i64;

        let relationships =
            vec![create_test_relationship(vault, "doc:readme", "viewer", "user:alice")];

        let result = write_test_relationships(&state, vault, relationships).await;
        assert!(result.is_ok());

        let revision = result.unwrap();
        assert!(revision.0 > 0);
    }
}
