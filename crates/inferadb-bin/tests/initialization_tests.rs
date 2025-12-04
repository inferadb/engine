//! Integration tests for system initialization
//!
//! Tests first-startup initialization flow, config file integration,
//! and subsequent startup behavior.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use inferadb_bin::initialization;
use inferadb_config::Config;
use inferadb_store::{InferaStore, MemoryBackend};

static TEST_ID_COUNTER: AtomicI64 = AtomicI64::new(10000000000000);

fn generate_test_id() -> i64 {
    TEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Test that first startup creates default account and vault
#[tokio::test]
async fn test_first_startup_creates_defaults() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let config = Config::default();

    // First call should create defaults
    let config1 = initialization::initialize_system(&store, &config)
        .await
        .expect("Initialization should succeed");

    assert_ne!(config1.default_vault, 0, "Vault should not be nil");
    assert_ne!(config1.default_organization, 0, "Account should not be nil");

    // Verify account exists
    let account = store
        .get_organization(config1.default_organization)
        .await
        .expect("Should retrieve account");
    assert!(account.is_some(), "Account should exist");
    assert_eq!(account.unwrap().name, "Default Organization", "Account name should match");

    // Verify vault exists
    let vault = store.get_vault(config1.default_vault).await.expect("Should retrieve vault");
    assert!(vault.is_some(), "Vault should exist");
    let vault = vault.unwrap();
    assert_eq!(vault.name, "Default Vault", "Vault name should match");
    assert_eq!(vault.organization, config1.default_organization, "Vault should belong to account");

    // Second call should return same config (idempotent)
    let config2 = initialization::initialize_system(&store, &config)
        .await
        .expect("Second initialization should succeed");
    assert_eq!(config1.default_vault, config2.default_vault, "Vault should be unchanged");
    assert_eq!(
        config1.default_organization, config2.default_organization,
        "Account should be unchanged"
    );

    // Verify no duplicate accounts/vaults created
    let all_accounts = store.list_organizations(None).await.expect("Should list accounts");
    assert_eq!(all_accounts.len(), 1, "Should have exactly one account after two initializations");

    let all_vaults = store
        .list_vaults_for_organization(config1.default_organization)
        .await
        .expect("Should list vaults");
    assert_eq!(all_vaults.len(), 1, "Should have exactly one vault after two initializations");
}

/// Test startup with config file values
#[tokio::test]
async fn test_startup_with_config_values() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let organization_id = generate_test_id();
    let vault_id = generate_test_id();

    let mut config = Config::default();
    config.multi_tenancy.default_organization = Some(organization_id.to_string());
    config.multi_tenancy.default_vault = Some(vault_id.to_string());

    // Should use config values
    let system_config = initialization::initialize_system(&store, &config)
        .await
        .expect("Initialization should succeed");

    assert_eq!(system_config.default_vault, vault_id, "Should use vault from config");
    assert_eq!(
        system_config.default_organization, organization_id,
        "Should use account from config"
    );

    // Verify account was created
    let account = store.get_organization(organization_id).await.expect("Should retrieve account");
    assert!(account.is_some(), "Account should be created");
    assert_eq!(account.unwrap().name, "Default Organization", "Account should have default name");

    // Verify vault was created
    let vault = store.get_vault(vault_id).await.expect("Should retrieve vault");
    assert!(vault.is_some(), "Vault should be created");
    let vault = vault.unwrap();
    assert_eq!(vault.name, "Default Vault", "Vault should have default name");
    assert_eq!(vault.organization, organization_id, "Vault should belong to account");
}

/// Test startup with existing account and vault
#[tokio::test]
async fn test_startup_with_existing_account_and_vault() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let organization_id = generate_test_id();
    let vault_id = generate_test_id();

    // Pre-create account with custom name
    let account =
        inferadb_types::Organization::with_id(organization_id, "My Custom Account".to_string());
    store.create_organization(account).await.expect("Should create account");

    // Pre-create vault with custom name
    let vault =
        inferadb_types::Vault::with_id(vault_id, organization_id, "My Custom Vault".to_string());
    store.create_vault(vault).await.expect("Should create vault");

    // Configure to use existing IDs
    let mut config = Config::default();
    config.multi_tenancy.default_organization = Some(organization_id.to_string());
    config.multi_tenancy.default_vault = Some(vault_id.to_string());

    // Should use existing resources
    let system_config = initialization::initialize_system(&store, &config)
        .await
        .expect("Initialization should succeed");

    assert_eq!(system_config.default_vault, vault_id, "Should use existing vault");
    assert_eq!(system_config.default_organization, organization_id, "Should use existing account");

    // Verify original names preserved
    let account = store
        .get_organization(organization_id)
        .await
        .expect("Should retrieve account")
        .expect("Account should exist");
    assert_eq!(account.name, "My Custom Account", "Account name should be preserved");

    let vault = store
        .get_vault(vault_id)
        .await
        .expect("Should retrieve vault")
        .expect("Vault should exist");
    assert_eq!(vault.name, "My Custom Vault", "Vault name should be preserved");
}

/// Test that vault must belong to specified account
#[tokio::test]
async fn test_vault_account_mismatch_error() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let organization_id_a = generate_test_id();
    let organization_id_b = generate_test_id();
    let vault_id = generate_test_id();

    // Create account A
    let account_a =
        inferadb_types::Organization::with_id(organization_id_a, "Account A".to_string());
    store.create_organization(account_a).await.expect("Should create account A");

    // Create vault owned by account A
    let vault = inferadb_types::Vault::with_id(vault_id, organization_id_a, "Vault A".to_string());
    store.create_vault(vault).await.expect("Should create vault");

    // Try to initialize with account B owning the vault
    let mut config = Config::default();
    config.multi_tenancy.default_organization = Some(organization_id_b.to_string());
    config.multi_tenancy.default_vault = Some(vault_id.to_string());

    // Should fail because vault belongs to different account
    let result = initialization::initialize_system(&store, &config).await;

    match result {
        Err(e) => {
            let error_message = format!("{:#}", e); // Use alt format to see all error context
            println!("Got expected error: {}", error_message);
            assert!(
                error_message.contains("belongs to account")
                    || error_message.contains("Failed to ensure vault exists"),
                "Error should mention vault/account mismatch, got: {}",
                error_message
            );
        },
        Ok(_) => {
            panic!("Should have failed when vault belongs to different account");
        },
    }
}

/// Test error handling for invalid UUID in config
#[tokio::test]
async fn test_invalid_uuid_in_config() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());

    let mut config = Config::default();
    config.multi_tenancy.default_organization = Some("not-a-uuid".to_string());
    config.multi_tenancy.default_vault = Some("also-not-a-uuid".to_string());

    // Should return error for invalid UUID
    let result = initialization::initialize_system(&store, &config).await;
    assert!(result.is_err(), "Should fail with invalid UUID");

    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("parse") || error_message.contains("UUID"),
        "Error should mention parsing or UUID, got: {}",
        error_message
    );
}

/// Test that SystemConfig is persisted correctly
#[tokio::test]
async fn test_system_config_persistence() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let config = Config::default();

    // Initialize system
    let system_config = initialization::initialize_system(&store, &config)
        .await
        .expect("Initialization should succeed");

    // Verify SystemConfig is stored
    let stored_config = store
        .get_system_config()
        .await
        .expect("Should retrieve system config")
        .expect("System config should exist");

    assert_eq!(
        stored_config.default_vault, system_config.default_vault,
        "Stored vault should match"
    );
    assert_eq!(
        stored_config.default_organization, system_config.default_organization,
        "Stored account should match"
    );
}

/// Test concurrent initialization (simulates race condition)
#[tokio::test]
async fn test_concurrent_initialization() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let config = Arc::new(Config::default());

    // Run multiple initializations concurrently
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let store = Arc::clone(&store);
            let config = Arc::clone(&config);
            tokio::spawn(async move { initialization::initialize_system(&store, &config).await })
        })
        .collect();

    // Wait for all to complete
    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("Task should not panic"))
        .collect();

    // All should succeed
    assert!(results.iter().all(|r| r.is_ok()), "All initializations should succeed");

    // All should return same vault and account
    let configs: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
    let first_config = &configs[0];

    for config in &configs {
        assert_eq!(config.default_vault, first_config.default_vault, "All should have same vault");
        assert_eq!(
            config.default_organization, first_config.default_organization,
            "All should have same account"
        );
    }

    // Verify only one account and vault created
    let all_accounts = store.list_organizations(None).await.expect("Should list accounts");
    assert_eq!(
        all_accounts.len(),
        1,
        "Should have exactly one account despite concurrent initialization"
    );

    let all_vaults = store
        .list_vaults_for_organization(first_config.default_organization)
        .await
        .expect("Should list vaults");
    assert_eq!(
        all_vaults.len(),
        1,
        "Should have exactly one vault despite concurrent initialization"
    );
}

// Note: Partial config (only vault or only account) is not supported.
// The system requires either both account AND vault to be specified, or neither.
// If neither is specified, both are auto-generated together.
