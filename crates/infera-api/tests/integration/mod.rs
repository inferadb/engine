//! Integration Test Framework
//!
//! This module provides common test utilities for integration tests:
//! - In-memory backend setup
//! - Test configuration
//! - Mock authentication
//! - Test state builders

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use infera_api::AppState;
use infera_config::Config;
use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use infera_store::MemoryBackend;
use infera_types::{AuthContext, AuthMethod, Relationship};

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

/// Create test configuration with auth disabled
pub fn create_test_config() -> Config {
    let mut config = Config::default();
    config.auth.enabled = false;
    config.server.rate_limiting_enabled = false;
    config.cache.enabled = true;
    config.cache.max_capacity = 1000;
    config.cache.ttl_seconds = 300;
    config
}

/// Create test configuration with auth enabled
pub fn create_test_config_with_auth() -> Config {
    let mut config = create_test_config();
    config.auth.enabled = true;
    config
}

/// Create test configuration with rate limiting enabled
pub fn create_test_config_with_rate_limiting() -> Config {
    let mut config = create_test_config();
    config.server.rate_limiting_enabled = true;
    config
}

/// Create test AppState with default configuration
pub fn create_test_state() -> AppState {
    create_test_state_with_config(create_test_config())
}

/// Create test AppState with custom configuration
pub fn create_test_state_with_config(config: Config) -> AppState {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();
    let default_vault = generate_test_id();
    let default_account = generate_test_id();

    AppState::new(
        store,
        schema,
        None, // No WASM host for tests
        Arc::new(config),
        None, // No JWKS cache for tests
        default_vault,
        default_account,
    )
}

/// Create test AppState with multiple vaults for multi-tenancy testing
pub fn create_multi_vault_test_state() -> (AppState, i64, i64, i64, i64) {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();

    let vault_a = generate_test_id();
    let organization_a = generate_test_id();
    let vault_b = generate_test_id();
    let organization_b = generate_test_id();

    let mut config = Config::default();
    config.auth.enabled = false; // Disable auth for simpler testing

    let state = AppState::new(
        store,
        schema,
        None, // No WASM host for tests
        Arc::new(config),
        None,    // No JWKS cache for tests
        vault_a, // Default to vault A
        organization_a,
    );

    (state, vault_a, organization_a, vault_b, organization_b)
}

/// Create mock AuthContext for testing
pub fn create_mock_auth_context(vault: i64, organization: i64, scopes: Vec<String>) -> AuthContext {
    AuthContext {
        tenant_id: "test_tenant".to_string(),
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
) -> Result<infera_types::Revision, Box<dyn std::error::Error>> {
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
        assert!(!config.auth.enabled);
        assert!(!config.server.rate_limiting_enabled);
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_create_test_config_with_auth() {
        let config = create_test_config_with_auth();
        assert!(config.auth.enabled);
    }

    #[test]
    fn test_create_test_config_with_rate_limiting() {
        let config = create_test_config_with_rate_limiting();
        assert!(config.server.rate_limiting_enabled);
    }

    #[test]
    fn test_create_test_state() {
        let state = create_test_state();
        assert!(!state.config.auth.enabled);
        assert!(state.default_vault != 0);
    }

    #[test]
    fn test_create_multi_vault_test_state() {
        let (state, vault_a, organization_a, vault_b, organization_b) =
            create_multi_vault_test_state();
        assert_ne!(vault_a, vault_b);
        assert_ne!(organization_a, organization_b);
        assert_eq!(state.default_vault, vault_a);
        assert_eq!(state.default_organization, organization_a);
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
