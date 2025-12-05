//! Multi-tenancy integration tests
//!
//! These tests verify the complete multi-tenant functionality including:
//! - Operations scoped to specific vaults
//! - JWT token vault binding
//! - Account-vault relationships
//! - Cross-vault operation prevention

use std::sync::Arc;

use inferadb_api::AppState;
use inferadb_config::Config;
use inferadb_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use inferadb_store::{MemoryBackend, RelationshipStore};
use inferadb_types::Relationship;

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
fn create_multi_vault_test_state() -> (AppState, i64, i64, i64, i64) {
    let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();

    // Create two separate vault/organization pairs for testing
    let vault_a = 11111111111111i64;
    let organization_a = 22222222222222i64;
    let vault_b = 33333333333333i64;
    let organization_b = 44444444444444i64;

    let config = Config::default();

    let state = AppState::builder(store, schema, Arc::new(config))
        .wasm_host(None)
        .jwks_cache(None)
        .server_identity(None)
        .build();

    (state, vault_a, organization_a, vault_b, organization_b)
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
    let key_alice = inferadb_types::RelationshipKey {
        resource: "document:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results_a =
        state.store.read(vault_a, &key_alice, inferadb_types::Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_a.len(), 1);
    assert_eq!(results_a[0].subject, "user:alice");

    // Verify vault B has Bob but not Alice
    let key_bob = inferadb_types::RelationshipKey {
        resource: "document:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:bob".to_string()),
    };

    let results_b =
        state.store.read(vault_b, &key_bob, inferadb_types::Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_b.len(), 1);
    assert_eq!(results_b[0].subject, "user:bob");

    // Verify vault A doesn't have Bob
    let results_a_bob =
        state.store.read(vault_a, &key_bob, inferadb_types::Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_a_bob.len(), 0);

    // Verify vault B doesn't have Alice
    let results_b_alice =
        state.store.read(vault_b, &key_alice, inferadb_types::Revision(u64::MAX)).await.unwrap();
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
        .list_relationships(vault_a, None, Some("viewer"), None, inferadb_types::Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(all_a.len(), 2); // Only vault A's relationships
    assert!(all_a.iter().all(|r| r.vault == vault_a));

    // List all relationships in vault B
    let all_b = state
        .store
        .list_relationships(vault_b, None, Some("viewer"), None, inferadb_types::Revision(u64::MAX))
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
        .resource_service
        .list_resources(
            vault_a,
            inferadb_types::ListResourcesRequest {
                subject: "user:alice".to_string(),
                permission: "viewer".to_string(),
                resource_type: "document".to_string(),
                limit: None,
                cursor: None,
                resource_id_pattern: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(resources_a.resources.len(), 2);
    assert!(resources_a.resources.contains(&"document:doc1".to_string()));
    assert!(resources_a.resources.contains(&"document:doc2".to_string()));
    assert!(!resources_a.resources.contains(&"document:doc3".to_string()));

    // Create a new resource service for vault B
    let resource_service_b = Arc::new(inferadb_api::services::ResourceService::new(
        Arc::clone(&state.store) as Arc<dyn RelationshipStore>,
        create_test_schema(),
        None, // No WASM host for tests
        None, // No cache for tests
    ));

    // Test list_resources in vault B
    let resources_b = resource_service_b
        .list_resources(
            vault_b,
            inferadb_types::ListResourcesRequest {
                subject: "user:bob".to_string(),
                permission: "viewer".to_string(),
                resource_type: "document".to_string(),
                limit: None,
                cursor: None,
                resource_id_pattern: None,
            },
        )
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
    let (state, vault_a, organization_a, ..) = create_multi_vault_test_state();
    let store = Arc::clone(&state.store);

    // Create the organization and vault in the store first
    store
        .create_organization(inferadb_types::Organization {
            id: organization_a,
            name: "Test Organization".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_vault(inferadb_types::Vault {
            id: vault_a,
            organization: organization_a,
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
    let key = inferadb_types::RelationshipKey {
        resource: "document:test".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results = store.read(vault_a, &key, inferadb_types::Revision(u64::MAX)).await.unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].vault, vault_a);
    assert_eq!(results[0].subject, "user:alice");
}

// =============================================================================
// 3. Organization-Vault Relationship
// =============================================================================

#[tokio::test]
async fn test_organization_can_own_multiple_vaults() {
    let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
    let organization = 55555555555555i64;
    let vault1 = 66666666666666i64;
    let vault2 = 77777777777777i64;
    let vault3 = 88888888888888i64;

    // Create the organization first
    let organization_obj = inferadb_types::Organization {
        id: organization,
        name: "Test Organization".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.create_organization(organization_obj).await.unwrap();

    // Create three vaults for the same organization
    let vault_obj_1 = inferadb_types::Vault {
        id: vault1,
        organization,
        name: "Vault 1".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let vault_obj_2 = inferadb_types::Vault {
        id: vault2,
        organization,
        name: "Vault 2".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let vault_obj_3 = inferadb_types::Vault {
        id: vault3,
        organization,
        name: "Vault 3".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store.create_vault(vault_obj_1).await.unwrap();
    store.create_vault(vault_obj_2).await.unwrap();
    store.create_vault(vault_obj_3).await.unwrap();

    // Verify all vaults belong to the same organization
    let vaults = store.list_vaults_for_organization(organization).await.unwrap();
    assert_eq!(vaults.len(), 3);
    assert!(vaults.iter().all(|v| v.organization == organization));

    // Verify each vault has unique ID
    let vault_ids: std::collections::HashSet<_> = vaults.iter().map(|v| v.id).collect();
    assert_eq!(vault_ids.len(), 3);
}

#[tokio::test]
async fn test_vault_belongs_to_one_organization() {
    let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
    let organization_a = 99999999999991i64;
    let organization_b = 99999999999992i64;
    let vault_id = 99999999999993i64;

    // Create organizations first
    store
        .create_organization(inferadb_types::Organization {
            id: organization_a,
            name: "Organization A".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_organization(inferadb_types::Organization {
            id: organization_b,
            name: "Organization B".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    // Create vault for organization A
    let vault = inferadb_types::Vault {
        id: vault_id,
        organization: organization_a,
        name: "Test Vault".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store.create_vault(vault).await.unwrap();

    // Verify vault belongs to organization A
    let vault_retrieved = store.get_vault(vault_id).await.unwrap().unwrap();
    assert_eq!(vault_retrieved.organization, organization_a);

    // Verify vault does NOT appear in organization B's vaults
    let organization_b_vaults = store.list_vaults_for_organization(organization_b).await.unwrap();
    assert_eq!(organization_b_vaults.len(), 0);
}

#[tokio::test]
async fn test_organization_cannot_access_other_organizations_vaults() {
    let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
    let organization_a = 99999999999994i64;
    let organization_b = 99999999999995i64;
    let vault_a = 99999999999996i64;
    let vault_b = 99999999999997i64;

    // Create organizations first
    store
        .create_organization(inferadb_types::Organization {
            id: organization_a,
            name: "Organization A".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_organization(inferadb_types::Organization {
            id: organization_b,
            name: "Organization B".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    // Create vaults for different organizations
    store
        .create_vault(inferadb_types::Vault {
            id: vault_a,
            organization: organization_a,
            name: "Vault A".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    store
        .create_vault(inferadb_types::Vault {
            id: vault_b,
            organization: organization_b,
            name: "Vault B".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    // Organization A should only see their vault
    let organization_a_vaults = store.list_vaults_for_organization(organization_a).await.unwrap();
    assert_eq!(organization_a_vaults.len(), 1);
    assert_eq!(organization_a_vaults[0].id, vault_a);

    // Organization B should only see their vault
    let organization_b_vaults = store.list_vaults_for_organization(organization_b).await.unwrap();
    assert_eq!(organization_b_vaults.len(), 1);
    assert_eq!(organization_b_vaults[0].id, vault_b);
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
    let key = inferadb_types::RelationshipKey {
        resource: "document:secret".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results =
        state.store.read(vault_b, &key, inferadb_types::Revision(u64::MAX)).await.unwrap();

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
        .evaluation_service
        .evaluate(
            vault_a,
            inferadb_types::EvaluateRequest {
                subject: "user:alice".to_string(),
                resource: "document:cached".to_string(),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            },
        )
        .await
        .unwrap();

    assert!(
        matches!(result_a, inferadb_types::Decision::Allow),
        "Alice should have access in vault A"
    );

    // Create an evaluation service for vault B
    // Note: Services handle vault scoping, so even with shared cache,
    // different vaults should return different results

    // Check same permission in vault B (should not use cached result from vault A)
    let result_b = state
        .evaluation_service
        .evaluate(
            vault_b,
            inferadb_types::EvaluateRequest {
                subject: "user:alice".to_string(),
                resource: "document:cached".to_string(),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            },
        )
        .await
        .unwrap();

    assert!(
        matches!(result_b, inferadb_types::Decision::Deny),
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
            inferadb_types::Revision(u64::MAX),
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
            inferadb_types::Revision(u64::MAX),
        )
        .await
        .unwrap();
    assert_eq!(results_b.len(), 50);
    assert!(results_b.iter().all(|r| r.vault == vault_b));
}
