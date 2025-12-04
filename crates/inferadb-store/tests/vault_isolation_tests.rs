//! Vault isolation tests
//!
//! These tests verify complete isolation between vaults at the storage level.
//! They ensure that no data leakage occurs between different vaults.

use std::sync::Arc;

use inferadb_store::{InferaStore, MemoryBackend};
use inferadb_test_fixtures::test_relationship_with_vault;
use inferadb_types::{DeleteFilter, Relationship, RelationshipKey, Revision};

// Test constants for concurrent operations
/// Number of concurrent write operations per vault in basic concurrency tests.
/// This value is chosen to be large enough to expose race conditions
/// while remaining fast enough for CI environments (<1s execution time).
const CONCURRENT_WRITES_BASIC: usize = 100;

/// Number of concurrent read-write operations per vault in load tests.
/// Higher value to stress-test vault isolation under realistic load.
const CONCURRENT_OPS_LOAD: usize = 200;

/// Helper to create a relationship for a specific vault
fn create_relationship(vault: i64, resource: &str, relation: &str, subject: &str) -> Relationship {
    test_relationship_with_vault(vault, resource, relation, subject)
}

// =============================================================================
// 1. Storage-Level Isolation
// =============================================================================

#[tokio::test]
async fn test_relationships_written_to_vault_a_not_visible_in_vault_b() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let vault_a = 111111111111i64;
    let vault_b = 222222222222i64;

    // Write to vault A
    store
        .write(
            vault_a,
            vec![create_relationship(vault_a, "document:secret_a", "viewer", "user:alice")],
        )
        .await
        .unwrap();

    // Write to vault B
    store
        .write(
            vault_b,
            vec![create_relationship(vault_b, "document:secret_b", "viewer", "user:bob")],
        )
        .await
        .unwrap();

    // Verify vault A can see its own data
    let key_a = RelationshipKey {
        resource: "document:secret_a".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let results_a = store
        .read(vault_a, &key_a, Revision(u64::MAX))
        .await
        .expect("Storage operation should succeed");
    assert_eq!(results_a.len(), 1);

    // Verify vault A cannot see vault B's data
    let key_b = RelationshipKey {
        resource: "document:secret_b".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:bob".to_string()),
    };
    let results_a_tries_b = store
        .read(vault_a, &key_b, Revision(u64::MAX))
        .await
        .expect("Storage operation should succeed");
    assert_eq!(results_a_tries_b.len(), 0, "Vault A should not see vault B's data");

    // Verify vault B can see its own data
    let results_b = store
        .read(vault_b, &key_b, Revision(u64::MAX))
        .await
        .expect("Storage operation should succeed");
    assert_eq!(results_b.len(), 1);

    // Verify vault B cannot see vault A's data
    let results_b_tries_a = store
        .read(vault_b, &key_a, Revision(u64::MAX))
        .await
        .expect("Storage operation should succeed");
    assert_eq!(results_b_tries_a.len(), 0, "Vault B should not see vault A's data");
}

#[tokio::test]
async fn test_concurrent_writes_to_different_vaults_dont_interfere() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let vault_a = 333333333333i64;
    let vault_b = 444444444444i64;
    let vault_c = 555555555555i64;

    // Spawn concurrent writes
    let store_a = Arc::clone(&store);
    let handle_a = tokio::spawn(async move {
        for i in 0..CONCURRENT_WRITES_BASIC {
            store_a
                .write(
                    vault_a,
                    vec![create_relationship(
                        vault_a,
                        &format!("doc:a{}", i),
                        "view",
                        "user:alice",
                    )],
                )
                .await
                .unwrap();
        }
    });

    let store_b = Arc::clone(&store);
    let handle_b = tokio::spawn(async move {
        for i in 0..CONCURRENT_WRITES_BASIC {
            store_b
                .write(
                    vault_b,
                    vec![create_relationship(vault_b, &format!("doc:b{}", i), "view", "user:bob")],
                )
                .await
                .unwrap();
        }
    });

    let store_c = Arc::clone(&store);
    let handle_c = tokio::spawn(async move {
        for i in 0..CONCURRENT_WRITES_BASIC {
            store_c
                .write(
                    vault_c,
                    vec![create_relationship(
                        vault_c,
                        &format!("doc:c{}", i),
                        "view",
                        "user:carol",
                    )],
                )
                .await
                .unwrap();
        }
    });

    // Wait for completion
    handle_a.await.expect("Storage operation should succeed");
    handle_b.await.expect("Storage operation should succeed");
    handle_c.await.expect("Storage operation should succeed");

    // Verify each vault has exactly 100 relationships
    // List all relationships with the "view" relation for each vault
    let results_a = store
        .list_relationships(vault_a, None, Some("view"), None, Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(results_a.len(), 100);
    assert!(results_a.iter().all(|r| r.vault == vault_a));

    let results_b = store
        .list_relationships(vault_b, None, Some("view"), None, Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(results_b.len(), 100);
    assert!(results_b.iter().all(|r| r.vault == vault_b));

    let results_c = store
        .list_relationships(vault_c, None, Some("view"), None, Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(results_c.len(), 100);
    assert!(results_c.iter().all(|r| r.vault == vault_c));
}

#[tokio::test]
async fn test_revision_tokens_are_vault_scoped() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let vault_a = 666666666666i64;
    let vault_b = 777777777777i64;

    // Write to vault A
    let rev_a1 = store
        .write(vault_a, vec![create_relationship(vault_a, "document:test", "view", "user:alice")])
        .await
        .unwrap();

    // Write to vault B
    let rev_b1 = store
        .write(vault_b, vec![create_relationship(vault_b, "document:test", "view", "user:bob")])
        .await
        .unwrap();

    // Write again to vault A
    let rev_a2 = store
        .write(vault_a, vec![create_relationship(vault_a, "document:test2", "view", "user:alice")])
        .await
        .unwrap();

    // Verify revisions are independent: each vault has its own counter starting at 0
    // Vault A has written twice, so should be at revision 2
    // Vault B has written once, so should be at revision 1
    assert_eq!(rev_a1, Revision(1), "Vault A's first write should be revision 1");
    assert_eq!(
        rev_b1,
        Revision(1),
        "Vault B's first write should also be revision 1 (independent counter)"
    );
    assert_eq!(rev_a2, Revision(2), "Vault A's second write should be revision 2");

    // Verify we can get vault-specific revisions
    let current_a = store.get_revision(vault_a).await.expect("Storage operation should succeed");
    let current_b = store.get_revision(vault_b).await.expect("Storage operation should succeed");

    assert_eq!(current_a, rev_a2, "Current revision for vault A should match latest write");
    assert_eq!(current_b, rev_b1, "Current revision for vault B should match its only write");
    assert_eq!(current_a, Revision(2), "Vault A should be at revision 2");
    assert_eq!(current_b, Revision(1), "Vault B should be at revision 1");
}

#[tokio::test]
async fn test_delete_operations_only_affect_target_vault() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let vault_a = 888888888888i64;
    let vault_b = 999999999999i64;

    // Write same relationship key to both vaults
    store
        .write(
            vault_a,
            vec![create_relationship(vault_a, "document:shared", "viewer", "user:alice")],
        )
        .await
        .unwrap();

    store
        .write(
            vault_b,
            vec![create_relationship(vault_b, "document:shared", "viewer", "user:alice")],
        )
        .await
        .unwrap();

    // Delete from vault A
    let key = RelationshipKey {
        resource: "document:shared".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    store.delete(vault_a, &key).await.expect("Storage operation should succeed");

    // Verify deleted from vault A
    let results_a = store
        .read(vault_a, &key, Revision(u64::MAX))
        .await
        .expect("Storage operation should succeed");
    assert_eq!(results_a.len(), 0, "Should be deleted from vault A");

    // Verify still exists in vault B
    let results_b = store
        .read(vault_b, &key, Revision(u64::MAX))
        .await
        .expect("Storage operation should succeed");
    assert_eq!(results_b.len(), 1, "Should still exist in vault B");
}

// =============================================================================
// 2. Cache Isolation (verify Phase 6)
// =============================================================================

#[tokio::test]
#[ignore = "Cache tests belong in infera-cache crate tests"]
async fn test_cache_keys_include_vault_uuid() {
    // This test has been moved to infera-cache crate tests
    // See crates/infera-cache/tests/vault_cache_isolation_tests.rs
}

#[tokio::test]
#[ignore = "Cache tests belong in infera-cache crate tests"]
async fn test_cache_invalidation_only_affects_target_vault() {
    // This test has been moved to infera-cache crate tests
    // See crates/infera-cache/tests/vault_cache_isolation_tests.rs
}

#[tokio::test]
#[ignore = "Cache tests belong in infera-cache crate tests"]
async fn test_no_cache_leakage_between_vaults() {
    // This test has been moved to infera-cache crate tests
    // See crates/infera-cache/tests/vault_cache_isolation_tests.rs
}

// =============================================================================
// 3. Query Isolation
// =============================================================================

#[tokio::test]
async fn test_filter_based_operations_scoped_to_vault() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let vault_a = 111111111112i64;
    let vault_b = 222222222223i64;

    // Write relationships to both vaults
    store
        .write(
            vault_a,
            vec![
                create_relationship(vault_a, "document:a1", "viewer", "user:alice"),
                create_relationship(vault_a, "document:a2", "viewer", "user:alice"),
                create_relationship(vault_a, "document:a3", "editor", "user:alice"),
            ],
        )
        .await
        .unwrap();

    store
        .write(
            vault_b,
            vec![
                create_relationship(vault_b, "document:b1", "viewer", "user:alice"),
                create_relationship(vault_b, "document:b2", "viewer", "user:alice"),
            ],
        )
        .await
        .unwrap();

    // Delete by filter in vault A (all viewer relations)
    let filter = DeleteFilter {
        resource: None,
        relation: Some("viewer".to_string()),
        subject: Some("user:alice".to_string()),
    };

    let (_, deleted) = store
        .delete_by_filter(vault_a, &filter, None)
        .await
        .expect("Storage operation should succeed");

    assert_eq!(deleted, 2, "Should delete 2 viewer relationships from vault A");

    // Verify vault A has only editor relationship left
    let remaining_a = store
        .list_relationships(vault_a, None, None, Some("user:alice"), Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(remaining_a.len(), 1);
    assert_eq!(remaining_a[0].relation, "editor");

    // Verify vault B still has all 2 relationships
    let remaining_b = store
        .list_relationships(vault_b, None, None, Some("user:alice"), Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(remaining_b.len(), 2);
    assert!(remaining_b.iter().all(|r| r.relation == "viewer"));
}

// =============================================================================
// 4. Stress Testing
// =============================================================================

#[tokio::test]
async fn test_100_vaults_with_concurrent_operations() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let vault_count = 100;
    let ops_per_vault = 10;

    // Create 100 vaults
    let vaults: Vec<i64> = (0..vault_count).map(|i| 10000000000i64 + i as i64).collect();

    // Spawn concurrent operations for each vault
    let mut handles = vec![];
    for (idx, vault) in vaults.iter().enumerate() {
        let store_clone = Arc::clone(&store);
        let vault_id = *vault;

        let handle = tokio::spawn(async move {
            for i in 0..ops_per_vault {
                store_clone
                    .write(
                        vault_id,
                        vec![create_relationship(
                            vault_id,
                            &format!("doc:v{}_{}", idx, i),
                            "view",
                            &format!("user:u{}", idx),
                        )],
                    )
                    .await
                    .unwrap();
            }
        });

        handles.push(handle);
    }

    // Wait for all operations
    for handle in handles {
        handle.await.expect("Storage operation should succeed");
    }

    // Verify each vault has exactly ops_per_vault relationships
    for vault in vaults {
        let results = store
            .list_relationships(vault, None, Some("view"), None, Revision(u64::MAX))
            .await
            .unwrap();
        assert_eq!(
            results.len(),
            ops_per_vault,
            "Each vault should have {} relationships",
            ops_per_vault
        );
        assert!(
            results.iter().all(|r| r.vault == vault),
            "All relationships should belong to the correct vault"
        );
    }
}

#[tokio::test]
async fn test_vault_isolation_under_load() {
    let store: Arc<dyn InferaStore> = Arc::new(MemoryBackend::new());
    let vault_a = 333333333334i64;
    let vault_b = 444444444445i64;

    // Concurrent reads and writes to different vaults
    let store_a = Arc::clone(&store);
    let handle_a = tokio::spawn(async move {
        for i in 0..CONCURRENT_OPS_LOAD {
            // Write
            store_a
                .write(
                    vault_a,
                    vec![create_relationship(
                        vault_a,
                        &format!("doc:a{}", i),
                        "view",
                        "user:alice",
                    )],
                )
                .await
                .unwrap();

            // Read
            let key = RelationshipKey {
                resource: format!("doc:a{}", i),
                relation: "view".to_string(),
                subject: Some("user:alice".to_string()),
            };
            let results = store_a
                .read(vault_a, &key, Revision(u64::MAX))
                .await
                .expect("Storage operation should succeed");
            assert_eq!(results.len(), 1);
        }
    });

    let store_b = Arc::clone(&store);
    let handle_b = tokio::spawn(async move {
        for i in 0..CONCURRENT_OPS_LOAD {
            // Write
            store_b
                .write(
                    vault_b,
                    vec![create_relationship(vault_b, &format!("doc:b{}", i), "view", "user:bob")],
                )
                .await
                .unwrap();

            // Read
            let key = RelationshipKey {
                resource: format!("doc:b{}", i),
                relation: "view".to_string(),
                subject: Some("user:bob".to_string()),
            };
            let results = store_b
                .read(vault_b, &key, Revision(u64::MAX))
                .await
                .expect("Storage operation should succeed");
            assert_eq!(results.len(), 1);
        }
    });

    handle_a.await.expect("Storage operation should succeed");
    handle_b.await.expect("Storage operation should succeed");

    // Final verification: each vault has exactly 200 relationships
    let results_a = store
        .list_relationships(vault_a, None, Some("view"), None, Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(results_a.len(), 200);

    let results_b = store
        .list_relationships(vault_b, None, Some("view"), None, Revision(u64::MAX))
        .await
        .unwrap();
    assert_eq!(results_b.len(), 200);
}
