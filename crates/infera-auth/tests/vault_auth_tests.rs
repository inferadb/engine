//! Integration tests for vault-scoped authentication
//!
//! These tests verify Phase 2 of multi-tenancy implementation:
//! - Vault and account fields in JWT tokens
//! - Vault validation middleware
//! - Multi-tenant isolation
//! - Default vault mode

use chrono::Utc;
use infera_auth::{
    context::{AuthContext, AuthMethod},
    validate_vault_access, AuthError,
};
use uuid::Uuid;

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
    assert!(
        result.is_ok(),
        "Valid vault UUID should pass validation: {:?}",
        result
    );
}

#[test]
fn test_vault_validation_rejects_nil_vault() {
    let nil_vault = Uuid::nil();
    let account_id = Uuid::new_v4();
    let auth = create_auth_context(nil_vault, account_id, "tenant-a");

    let result = validate_vault_access(&auth);
    assert!(
        result.is_err(),
        "Nil vault UUID should be rejected"
    );
    match result {
        Err(AuthError::InvalidTokenFormat(msg)) => {
            assert!(
                msg.contains("vault") || msg.contains("nil"),
                "Error message should mention vault or nil: {}",
                msg
            );
        }
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
    assert!(
        validate_vault_access(&auth_a).is_ok(),
        "Tenant A vault should be valid"
    );
    assert!(
        validate_vault_access(&auth_b).is_ok(),
        "Tenant B vault should be valid"
    );

    // Vaults should be different (isolation)
    assert_ne!(
        auth_a.vault, auth_b.vault,
        "Different tenants should have different vaults"
    );
    assert_ne!(
        auth_a.account, auth_b.account,
        "Different tenants should have different accounts"
    );
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
    assert!(
        validate_vault_access(&auth).is_ok(),
        "Valid vault and account should pass validation"
    );
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
    assert!(
        validate_vault_access(&auth).is_ok(),
        "Default vault should pass validation"
    );
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
    assert_ne!(
        auth_a.account, auth_b.account,
        "Accounts should be different"
    );
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

    assert!(
        validate_vault_access(&auth).is_ok(),
        "Max UUID vault should be valid"
    );

    // Test with another random UUID
    let vault_v2 = Uuid::new_v4();
    let auth_v2 = create_auth_context(vault_v2, account_id, "tenant-b");

    assert!(
        validate_vault_access(&auth_v2).is_ok(),
        "Random UUID vault should be valid"
    );
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
    use std::sync::Arc;
    use std::thread;

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
