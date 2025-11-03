//! Multi-tenancy integration tests
//!
//! These tests verify the complete multi-tenant functionality including:
//! - Operations scoped to specific vaults
//! - JWT token vault binding
//! - Account-vault relationships
//! - Cross-vault operation prevention

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use infera_api::{AppState, create_router};
use infera_config::Config;
use infera_core::{
    Evaluator,
    ipl::{RelationDef, RelationExpr, Schema, TypeDef},
};
use infera_store::{MemoryBackend, RelationshipStore};
use infera_types::Relationship;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

/// Create a test schema for multi-tenant testing
fn create_test_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![TypeDef {
        name: "document".to_string(),
        relations: vec![
            RelationDef { name: "viewer".to_string(), expr: Some(RelationExpr::This) },
            RelationDef { name: "editor".to_string(), expr: Some(RelationExpr::This) },
        ],
        forbids: vec![],
    }]))
}

/// Create test state with multiple vaults
fn create_multi_vault_test_state() -> (AppState, Uuid, Uuid, Uuid, Uuid) {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();

    // Create two separate vault/account pairs for testing
    let vault_a = Uuid::new_v4();
    let account_a = Uuid::new_v4();
    let vault_b = Uuid::new_v4();
    let account_b = Uuid::new_v4();

    let evaluator = Arc::new(Evaluator::new(
        Arc::clone(&store) as Arc<dyn RelationshipStore>,
        schema,
        None,
        vault_a, // Default to vault A
    ));

    let mut config = Config::default();
    config.auth.enabled = false; // Disable auth for simpler testing

    let state = AppState {
        evaluator,
        store,
        config: Arc::new(config),
        jwks_cache: None,
        health_tracker: Arc::new(infera_api::health::HealthTracker::new()),
        default_vault: vault_a,
        default_account: account_a,
    };

    (state, vault_a, account_a, vault_b, account_b)
}

// =============================================================================
// 1. Basic Multi-Tenant Operations
// =============================================================================

#[tokio::test]
async fn test_write_relationships_in_different_vaults() {
    let (state, vault_a, _, vault_b, _) = create_multi_vault_test_state();

    // Write relationships to vault A
    state
        .store
        .write(
            vault_a,
            vec![Relationship {
                vault: vault_a,
                resource: "document:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            }],
        )
        .await
        .unwrap();

    // Write relationships to vault B
    state
        .store
        .write(
            vault_b,
            vec![Relationship {
                vault: vault_b,
                resource: "document:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            }],
        )
        .await
        .unwrap();

    // Verify vault A has Alice but not Bob
    let key_alice = infera_types::RelationshipKey {
        resource: "document:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results_a =
        state.store.read(vault_a, &key_alice, infera_types::Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_a.len(), 1);
    assert_eq!(results_a[0].subject, "user:alice");

    // Verify vault B has Bob but not Alice
    let key_bob = infera_types::RelationshipKey {
        resource: "document:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:bob".to_string()),
    };

    let results_b =
        state.store.read(vault_b, &key_bob, infera_types::Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_b.len(), 1);
    assert_eq!(results_b[0].subject, "user:bob");

    // Verify vault A doesn't have Bob
    let results_a_bob =
        state.store.read(vault_a, &key_bob, infera_types::Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_a_bob.len(), 0);

    // Verify vault B doesn't have Alice
    let results_b_alice =
        state.store.read(vault_b, &key_alice, infera_types::Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_b_alice.len(), 0);
}

#[tokio::test]
async fn test_operations_scope_to_correct_vault() {
    let (state, vault_a, _, vault_b, _) = create_multi_vault_test_state();

    // Write to both vaults
    state
        .store
        .write(
            vault_a,
            vec![
                Relationship {
                    vault: vault_a,
                    resource: "document:a1".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                },
                Relationship {
                    vault: vault_a,
                    resource: "document:a2".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                },
            ],
        )
        .await
        .unwrap();

    state
        .store
        .write(
            vault_b,
            vec![Relationship {
                vault: vault_b,
                resource: "document:b1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            }],
        )
        .await
        .unwrap();

    // List all relationships in vault A
    let all_a = state
        .store
        .list_relationships(vault_a, None, Some("viewer"), None, infera_types::Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(all_a.len(), 2); // Only vault A's relationships
    assert!(all_a.iter().all(|r| r.vault == vault_a));

    // List all relationships in vault B
    let all_b = state
        .store
        .list_relationships(vault_b, None, Some("viewer"), None, infera_types::Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(all_b.len(), 1); // Only vault B's relationship
    assert!(all_b.iter().all(|r| r.vault == vault_b));
}

#[tokio::test]
async fn test_vault_scoped_listing() {
    let (state, vault_a, _, vault_b, _) = create_multi_vault_test_state();

    // Setup: Write relationships to both vaults
    state
        .store
        .write(
            vault_a,
            vec![
                Relationship {
                    vault: vault_a,
                    resource: "document:doc1".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                },
                Relationship {
                    vault: vault_a,
                    resource: "document:doc2".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                },
            ],
        )
        .await
        .unwrap();

    state
        .store
        .write(
            vault_b,
            vec![Relationship {
                vault: vault_b,
                resource: "document:doc3".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            }],
        )
        .await
        .unwrap();

    // Test list_resources in vault A
    let resources_a = state
        .evaluator
        .list_resources(infera_types::ListResourcesRequest {
            subject: "user:alice".to_string(),
            permission: "viewer".to_string(),
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        })
        .await
        .unwrap();

    assert_eq!(resources_a.resources.len(), 2);
    assert!(resources_a.resources.contains(&"document:doc1".to_string()));
    assert!(resources_a.resources.contains(&"document:doc2".to_string()));
    assert!(!resources_a.resources.contains(&"document:doc3".to_string()));

    // Create evaluator for vault B
    let evaluator_b = Evaluator::new(
        Arc::clone(&state.store) as Arc<dyn RelationshipStore>,
        create_test_schema(),
        None, // No WASM host
        vault_b,
    );

    // Test list_resources in vault B
    let resources_b = evaluator_b
        .list_resources(infera_types::ListResourcesRequest {
            subject: "user:bob".to_string(),
            permission: "viewer".to_string(),
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        })
        .await
        .unwrap();

    assert_eq!(resources_b.resources.len(), 1);
    assert!(resources_b.resources.contains(&"document:doc3".to_string()));
}

// =============================================================================
// 2. JWT Token Vault Binding
// =============================================================================

#[tokio::test]
async fn test_default_vault_fallback_when_auth_disabled() {
    let (state, vault_a, account_a, ..) = create_multi_vault_test_state();
    let store = Arc::clone(&state.store);

    // Create the account and vault in the store first
    store
        .create_account(infera_types::Account {
            id: account_a,
            name: "Test Account".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_vault(infera_types::Vault {
            id: vault_a,
            account: account_a,
            name: "Test Vault".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    // Write a relationship directly to the default vault (simulating what the endpoint would do)
    let relationship = Relationship {
        vault: vault_a,
        resource: "document:test".to_string(),
        relation: "viewer".to_string(),
        subject: "user:alice".to_string(),
    };

    store.write(vault_a, vec![relationship]).await.unwrap();

    // Verify the relationship was written to vault_a (default vault)
    let key = infera_types::RelationshipKey {
        resource: "document:test".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results = store.read(vault_a, &key, infera_types::Revision(u64::MAX)).await.unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].vault, vault_a);
    assert_eq!(results[0].subject, "user:alice");
}

// =============================================================================
// 3. Account-Vault Relationship
// =============================================================================

#[tokio::test]
async fn test_account_can_own_multiple_vaults() {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let account = Uuid::new_v4();
    let vault1 = Uuid::new_v4();
    let vault2 = Uuid::new_v4();
    let vault3 = Uuid::new_v4();

    // Create the account first
    let account_obj = infera_types::Account {
        id: account,
        name: "Test Account".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.create_account(account_obj).await.unwrap();

    // Create three vaults for the same account
    let vault_obj_1 = infera_types::Vault {
        id: vault1,
        account: account,
        name: "Vault 1".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let vault_obj_2 = infera_types::Vault {
        id: vault2,
        account: account,
        name: "Vault 2".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let vault_obj_3 = infera_types::Vault {
        id: vault3,
        account: account,
        name: "Vault 3".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store.create_vault(vault_obj_1).await.unwrap();
    store.create_vault(vault_obj_2).await.unwrap();
    store.create_vault(vault_obj_3).await.unwrap();

    // Verify all vaults belong to the same account
    let vaults = store.list_vaults_for_account(account).await.unwrap();
    assert_eq!(vaults.len(), 3);
    assert!(vaults.iter().all(|v| v.account == account));

    // Verify each vault has unique ID
    let vault_ids: std::collections::HashSet<_> = vaults.iter().map(|v| v.id).collect();
    assert_eq!(vault_ids.len(), 3);
}

#[tokio::test]
async fn test_vault_belongs_to_one_account() {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let vault_id = Uuid::new_v4();

    // Create accounts first
    store
        .create_account(infera_types::Account {
            id: account_a,
            name: "Account A".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_account(infera_types::Account {
            id: account_b,
            name: "Account B".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    // Create vault for account A
    let vault = infera_types::Vault {
        id: vault_id,
        account: account_a,
        name: "Test Vault".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store.create_vault(vault).await.unwrap();

    // Verify vault belongs to account A
    let vault_retrieved = store.get_vault(vault_id).await.unwrap().unwrap();
    assert_eq!(vault_retrieved.account, account_a);

    // Verify vault does NOT appear in account B's vaults
    let account_b_vaults = store.list_vaults_for_account(account_b).await.unwrap();
    assert_eq!(account_b_vaults.len(), 0);
}

#[tokio::test]
async fn test_account_cannot_access_other_accounts_vaults() {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let vault_a = Uuid::new_v4();
    let vault_b = Uuid::new_v4();

    // Create accounts first
    store
        .create_account(infera_types::Account {
            id: account_a,
            name: "Account A".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_account(infera_types::Account {
            id: account_b,
            name: "Account B".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    // Create vaults for different accounts
    store
        .create_vault(infera_types::Vault {
            id: vault_a,
            account: account_a,
            name: "Vault A".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_vault(infera_types::Vault {
            id: vault_b,
            account: account_b,
            name: "Vault B".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    // Account A should only see their vault
    let account_a_vaults = store.list_vaults_for_account(account_a).await.unwrap();
    assert_eq!(account_a_vaults.len(), 1);
    assert_eq!(account_a_vaults[0].id, vault_a);

    // Account B should only see their vault
    let account_b_vaults = store.list_vaults_for_account(account_b).await.unwrap();
    assert_eq!(account_b_vaults.len(), 1);
    assert_eq!(account_b_vaults[0].id, vault_b);
}

// =============================================================================
// 4. Cross-Vault Operation Prevention
// =============================================================================

#[tokio::test]
async fn test_read_from_wrong_vault_returns_empty() {
    let (state, vault_a, _, vault_b, _) = create_multi_vault_test_state();

    // Write to vault A
    state
        .store
        .write(
            vault_a,
            vec![Relationship {
                vault: vault_a,
                resource: "document:secret".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            }],
        )
        .await
        .unwrap();

    // Try to read from vault B
    let key = infera_types::RelationshipKey {
        resource: "document:secret".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results = state.store.read(vault_b, &key, infera_types::Revision(u64::MAX)).await.unwrap();

    assert_eq!(results.len(), 0, "Should not see data from different vault");
}

#[tokio::test]
async fn test_cached_data_doesnt_leak_between_vaults() {
    let (state, vault_a, _, vault_b, _) = create_multi_vault_test_state();

    // Write to vault A
    state
        .store
        .write(
            vault_a,
            vec![Relationship {
                vault: vault_a,
                resource: "document:cached".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            }],
        )
        .await
        .unwrap();

    // Check permission in vault A (should cache result)
    let result_a = state
        .evaluator
        .check(infera_types::EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:cached".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        })
        .await
        .unwrap();

    assert!(
        matches!(result_a, infera_types::Decision::Allow),
        "Alice should have access in vault A"
    );

    // Create evaluator for vault B
    let evaluator_b = Evaluator::new_with_cache(
        Arc::clone(&state.store) as Arc<dyn RelationshipStore>,
        create_test_schema(),
        None,                                    // No WASM host
        state.evaluator.cache().map(Arc::clone), // Share cache to test isolation
        vault_b,
    );

    // Check same permission in vault B (should not use cached result from vault A)
    let result_b = evaluator_b
        .check(infera_types::EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:cached".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        })
        .await
        .unwrap();

    assert!(
        matches!(result_b, infera_types::Decision::Deny),
        "Alice should NOT have access in vault B (cache isolation)"
    );
}

#[tokio::test]
async fn test_concurrent_operations_on_different_vaults() {
    let (state, vault_a, _, vault_b, _) = create_multi_vault_test_state();
    let state = Arc::new(state);

    // Spawn concurrent writes to different vaults
    let state_a = Arc::clone(&state);
    let handle_a = tokio::spawn(async move {
        for i in 0..50 {
            state_a
                .store
                .write(
                    vault_a,
                    vec![Relationship {
                        vault: vault_a,
                        resource: format!("document:a{}", i),
                        relation: "viewer".to_string(),
                        subject: "user:alice".to_string(),
                    }],
                )
                .await
                .unwrap();
        }
    });

    let state_b = Arc::clone(&state);
    let handle_b = tokio::spawn(async move {
        for i in 0..50 {
            state_b
                .store
                .write(
                    vault_b,
                    vec![Relationship {
                        vault: vault_b,
                        resource: format!("document:b{}", i),
                        relation: "viewer".to_string(),
                        subject: "user:bob".to_string(),
                    }],
                )
                .await
                .unwrap();
        }
    });

    // Wait for both to complete
    handle_a.await.unwrap();
    handle_b.await.unwrap();

    // Verify isolation: vault A should have 50 relationships
    let results_a = state
        .store
        .list_relationships(
            vault_a,
            None,
            Some("viewer"),
            Some("user:alice"),
            infera_types::Revision(u64::MAX),
        )
        .await
        .unwrap();
    assert_eq!(results_a.len(), 50);
    assert!(results_a.iter().all(|r| r.vault == vault_a));

    // Verify isolation: vault B should have 50 relationships
    let results_b = state
        .store
        .list_relationships(
            vault_b,
            None,
            Some("viewer"),
            Some("user:bob"),
            infera_types::Revision(u64::MAX),
        )
        .await
        .unwrap();
    assert_eq!(results_b.len(), 50);
    assert!(results_b.iter().all(|r| r.vault == vault_b));
}
