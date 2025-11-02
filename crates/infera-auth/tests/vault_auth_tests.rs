//! Integration tests for vault-scoped authentication
//!
//! These tests verify Phase 2 of multi-tenancy implementation:
//! - Vault and account fields in JWT tokens
//! - Vault validation middleware
//! - Multi-tenant isolation
//! - Default vault mode

use async_trait::async_trait;
use chrono::Utc;
use infera_auth::{
    AuthError,
    context::{AuthContext, AuthMethod},
    validate_vault_access, validate_vault_access_with_store,
};
use infera_store::VaultStore;
use infera_types::{StoreResult, SystemConfig, Vault};
use uuid::Uuid;

/// Mock VaultStore for testing database validation
struct MockVaultStore {
    vaults: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<Uuid, Vault>>>,
}

impl MockVaultStore {
    fn new() -> Self {
        Self {
            vaults: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn insert_vault(&self, vault: Vault) {
        self.vaults.lock().unwrap().insert(vault.id, vault);
    }
}

#[async_trait]
impl VaultStore for MockVaultStore {
    async fn create_vault(&self, vault: Vault) -> StoreResult<Vault> {
        self.vaults.lock().unwrap().insert(vault.id, vault.clone());
        Ok(vault)
    }

    async fn get_vault(&self, id: Uuid) -> StoreResult<Option<Vault>> {
        Ok(self.vaults.lock().unwrap().get(&id).cloned())
    }

    async fn list_vaults_for_account(&self, account_id: Uuid) -> StoreResult<Vec<Vault>> {
        Ok(self
            .vaults
            .lock()
            .unwrap()
            .values()
            .filter(|v| v.account == account_id)
            .cloned()
            .collect())
    }

    async fn delete_vault(&self, id: Uuid) -> StoreResult<()> {
        self.vaults.lock().unwrap().remove(&id);
        Ok(())
    }

    async fn update_vault(&self, vault: Vault) -> StoreResult<Vault> {
        self.vaults.lock().unwrap().insert(vault.id, vault.clone());
        Ok(vault)
    }

    async fn get_system_config(&self) -> StoreResult<Option<SystemConfig>> {
        Ok(None)
    }

    async fn set_system_config(&self, _config: SystemConfig) -> StoreResult<()> {
        Ok(())
    }
}

/// Create a test AuthContext with specified vault and account
fn create_auth_context(vault: Uuid, account: Uuid, tenant_id: &str) -> AuthContext {
    AuthContext {
        tenant_id: tenant_id.to_string(),
        client_id: format!("client-{}", tenant_id),
        key_id: "test-key-001".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: vec![
            "inferadb.check".to_string(),
            "inferadb.write".to_string(),
            "inferadb.expand".to_string(),
        ],
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        jti: Some(Uuid::new_v4().to_string()),
        vault,
        account,
    }
}

#[test]
fn test_vault_validation_with_valid_vault() {
    let vault_id = Uuid::new_v4();
    let account_id = Uuid::new_v4();
    let auth = create_auth_context(vault_id, account_id, "tenant-a");

    let result = validate_vault_access(&auth);
    assert!(result.is_ok(), "Valid vault UUID should pass validation: {:?}", result);
}

#[test]
fn test_vault_validation_rejects_nil_vault() {
    let nil_vault = Uuid::nil();
    let account_id = Uuid::new_v4();
    let auth = create_auth_context(nil_vault, account_id, "tenant-a");

    let result = validate_vault_access(&auth);
    assert!(result.is_err(), "Nil vault UUID should be rejected");
    match result {
        Err(AuthError::InvalidTokenFormat(msg)) => {
            assert!(
                msg.contains("vault") || msg.contains("nil"),
                "Error message should mention vault or nil: {}",
                msg
            );
        },
        _ => panic!("Expected InvalidTokenFormat error"),
    }
}

#[test]
fn test_multi_tenant_vault_isolation() {
    // Create two separate tenants with different vaults
    let vault_a = Uuid::new_v4();
    let account_a = Uuid::new_v4();
    let auth_a = create_auth_context(vault_a, account_a, "tenant-a");

    let vault_b = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let auth_b = create_auth_context(vault_b, account_b, "tenant-b");

    // Both should pass validation individually
    assert!(validate_vault_access(&auth_a).is_ok(), "Tenant A vault should be valid");
    assert!(validate_vault_access(&auth_b).is_ok(), "Tenant B vault should be valid");

    // Vaults should be different (isolation)
    assert_ne!(auth_a.vault, auth_b.vault, "Different tenants should have different vaults");
    assert_ne!(auth_a.account, auth_b.account, "Different tenants should have different accounts");
}

#[test]
fn test_vault_and_account_relationship() {
    let vault_id = Uuid::new_v4();
    let account_id = Uuid::new_v4();
    let auth = create_auth_context(vault_id, account_id, "tenant-a");

    // Both vault and account should be non-nil
    assert!(!auth.vault.is_nil(), "Vault should not be nil");
    assert!(!auth.account.is_nil(), "Account should not be nil");

    // Validation should pass
    assert!(validate_vault_access(&auth).is_ok(), "Valid vault and account should pass validation");
}

#[test]
fn test_default_unauthenticated_context() {
    let default_vault = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let default_account = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();

    let auth = AuthContext::default_unauthenticated(default_vault, default_account);

    // Check that default context has expected properties
    assert_eq!(auth.tenant_id, "default");
    assert_eq!(auth.client_id, "system:unauthenticated");
    assert_eq!(auth.vault, default_vault);
    assert_eq!(auth.account, default_account);
    assert_eq!(auth.auth_method, AuthMethod::InternalServiceJwt);

    // Should have full scopes
    assert!(auth.has_scope("inferadb.check"));
    assert!(auth.has_scope("inferadb.write"));
    assert!(auth.has_scope("inferadb.expand"));

    // Should pass vault validation since it's not nil
    assert!(validate_vault_access(&auth).is_ok(), "Default vault should pass validation");
}

#[test]
fn test_vault_validation_with_same_vault_different_accounts() {
    // Edge case: same vault but different accounts (shouldn't happen in practice,
    // but tests isolation logic)
    let shared_vault = Uuid::new_v4();
    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();

    let auth_a = create_auth_context(shared_vault, account_a, "tenant-a");
    let auth_b = create_auth_context(shared_vault, account_b, "tenant-b");

    // Both should pass basic validation
    assert!(validate_vault_access(&auth_a).is_ok());
    assert!(validate_vault_access(&auth_b).is_ok());

    // Even with same vault, accounts should be different
    assert_eq!(auth_a.vault, auth_b.vault, "Vaults should be the same");
    assert_ne!(auth_a.account, auth_b.account, "Accounts should be different");
}

#[test]
fn test_vault_validation_preserves_all_context_fields() {
    let vault_id = Uuid::new_v4();
    let account_id = Uuid::new_v4();
    let auth = create_auth_context(vault_id, account_id, "tenant-test");

    // Validate and ensure all fields are preserved
    assert!(validate_vault_access(&auth).is_ok());

    // Check that validation doesn't modify the context
    assert_eq!(auth.vault, vault_id);
    assert_eq!(auth.account, account_id);
    assert_eq!(auth.tenant_id, "tenant-test");
    assert_eq!(auth.client_id, "client-tenant-test");
    assert!(!auth.scopes.is_empty());
}

#[test]
fn test_nil_account_with_valid_vault_still_passes() {
    // Account validation is not enforced yet (Phase 1 not implemented)
    // But vault must be non-nil
    let vault_id = Uuid::new_v4();
    let nil_account = Uuid::nil();
    let auth = create_auth_context(vault_id, nil_account, "tenant-a");

    // Should pass because we only validate vault, not account (for now)
    let result = validate_vault_access(&auth);
    assert!(
        result.is_ok(),
        "Valid vault with nil account should pass (account validation not yet implemented)"
    );
}

#[test]
fn test_vault_validation_with_special_uuids() {
    // Test with various special UUID values
    let vault_max = Uuid::from_u128(u128::MAX);
    let account_id = Uuid::new_v4();
    let auth = create_auth_context(vault_max, account_id, "tenant-a");

    assert!(validate_vault_access(&auth).is_ok(), "Max UUID vault should be valid");

    // Test with another random UUID
    let vault_v2 = Uuid::new_v4();
    let auth_v2 = create_auth_context(vault_v2, account_id, "tenant-b");

    assert!(validate_vault_access(&auth_v2).is_ok(), "Random UUID vault should be valid");
}

#[test]
fn test_auth_context_clone_preserves_vault() {
    let vault_id = Uuid::new_v4();
    let account_id = Uuid::new_v4();
    let auth = create_auth_context(vault_id, account_id, "tenant-a");

    // Clone the context
    let auth_cloned = auth.clone();

    // Verify vault and account are preserved
    assert_eq!(auth.vault, auth_cloned.vault);
    assert_eq!(auth.account, auth_cloned.account);
    assert_eq!(auth.tenant_id, auth_cloned.tenant_id);
}

#[test]
fn test_concurrent_vault_validations() {
    use std::{sync::Arc, thread};

    // Test that vault validation is thread-safe
    let vault_id = Arc::new(Uuid::new_v4());
    let account_id = Arc::new(Uuid::new_v4());

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let vault = Arc::clone(&vault_id);
            let account = Arc::clone(&account_id);

            thread::spawn(move || {
                let auth = create_auth_context(*vault, *account, &format!("tenant-{}", i));
                validate_vault_access(&auth)
            })
        })
        .collect();

    // All validations should succeed
    for handle in handles {
        let result = handle.join().expect("Thread should not panic");
        assert!(result.is_ok(), "Concurrent validation should succeed");
    }
}

// ============================================================================
// Database Validation Tests
// ============================================================================

#[tokio::test]
async fn test_validate_vault_access_with_store_success() {
    let store = MockVaultStore::new();
    let account_id = Uuid::new_v4();
    let vault_id = Uuid::new_v4();

    // Create and insert vault
    let vault = Vault::with_id(vault_id, account_id, "Test Vault".to_string());
    store.insert_vault(vault);

    // Create auth context
    let auth = create_auth_context(vault_id, account_id, "tenant-a");

    // Validation should succeed
    let result = validate_vault_access_with_store(&auth, &store).await;
    assert!(result.is_ok(), "Valid vault with matching account should pass: {:?}", result);
}

#[tokio::test]
async fn test_validate_vault_access_with_store_vault_not_found() {
    let store = MockVaultStore::new();
    let account_id = Uuid::new_v4();
    let nonexistent_vault = Uuid::new_v4();

    // Create auth context for vault that doesn't exist
    let auth = create_auth_context(nonexistent_vault, account_id, "tenant-a");

    // Validation should fail - vault doesn't exist
    let result = validate_vault_access_with_store(&auth, &store).await;
    assert!(result.is_err(), "Non-existent vault should be rejected");
    match result {
        Err(AuthError::InvalidTokenFormat(msg)) => {
            assert!(
                msg.contains("does not exist"),
                "Error should mention vault doesn't exist: {}",
                msg
            );
        },
        _ => panic!("Expected InvalidTokenFormat error"),
    }
}

#[tokio::test]
async fn test_validate_vault_access_with_store_wrong_account() {
    let store = MockVaultStore::new();
    let vault_account = Uuid::new_v4();
    let wrong_account = Uuid::new_v4();
    let vault_id = Uuid::new_v4();

    // Create vault owned by vault_account
    let vault = Vault::with_id(vault_id, vault_account, "Test Vault".to_string());
    store.insert_vault(vault);

    // Create auth context with wrong account
    let auth = create_auth_context(vault_id, wrong_account, "tenant-a");

    // Validation should fail - account mismatch
    let result = validate_vault_access_with_store(&auth, &store).await;
    assert!(result.is_err(), "Vault owned by different account should be rejected");
    match result {
        Err(AuthError::InvalidTokenFormat(msg)) => {
            assert!(
                msg.contains("does not own"),
                "Error should mention account doesn't own vault: {}",
                msg
            );
        },
        _ => panic!("Expected InvalidTokenFormat error"),
    }
}

#[tokio::test]
async fn test_validate_vault_access_with_store_nil_vault() {
    let store = MockVaultStore::new();
    let account_id = Uuid::new_v4();
    let nil_vault = Uuid::nil();

    // Create auth context with nil vault
    let auth = create_auth_context(nil_vault, account_id, "tenant-a");

    // Validation should fail - nil vault
    let result = validate_vault_access_with_store(&auth, &store).await;
    assert!(result.is_err(), "Nil vault should be rejected");
    match result {
        Err(AuthError::InvalidTokenFormat(msg)) => {
            assert!(msg.contains("nil"), "Error should mention nil vault: {}", msg);
        },
        _ => panic!("Expected InvalidTokenFormat error"),
    }
}

#[tokio::test]
async fn test_validate_vault_access_with_store_multiple_vaults() {
    let store = MockVaultStore::new();
    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let vault_a = Uuid::new_v4();
    let vault_b = Uuid::new_v4();

    // Create vaults for different accounts
    store.insert_vault(Vault::with_id(vault_a, account_a, "Vault A".to_string()));
    store.insert_vault(Vault::with_id(vault_b, account_b, "Vault B".to_string()));

    // Test vault A with account A - should succeed
    let auth_a = create_auth_context(vault_a, account_a, "tenant-a");
    assert!(
        validate_vault_access_with_store(&auth_a, &store).await.is_ok(),
        "Account A should access vault A"
    );

    // Test vault B with account B - should succeed
    let auth_b = create_auth_context(vault_b, account_b, "tenant-b");
    assert!(
        validate_vault_access_with_store(&auth_b, &store).await.is_ok(),
        "Account B should access vault B"
    );

    // Test vault A with account B - should fail
    let auth_cross = create_auth_context(vault_a, account_b, "tenant-b");
    assert!(
        validate_vault_access_with_store(&auth_cross, &store).await.is_err(),
        "Account B should not access vault A"
    );
}
