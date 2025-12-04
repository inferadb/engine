//! End-to-End Integration Tests
//!
//! These tests verify complete workflows across the API → evaluator → storage stack.
//!
//! Test scenarios:
//! - Write relationships → Read relationships back
//! - Vault isolation with identical resources
//! - Bulk operations
//! - Empty vault operations

use infera_types::{Relationship, RelationshipKey, Revision};

use crate::{
    create_multi_vault_test_state, create_test_relationship, create_test_state,
    write_test_relationships,
};

/// Test: Write relationships → Read them back
#[tokio::test]
async fn test_e2e_write_then_read() {
    let state = create_test_state();
    let vault = 11111111111111i64;

    // Write relationships
    let relationships = vec![
        create_test_relationship(vault, "doc:readme", "viewer", "user:alice"),
        create_test_relationship(vault, "doc:readme", "editor", "user:bob"),
        create_test_relationship(vault, "doc:guide", "viewer", "user:alice"),
    ];

    let write_result = write_test_relationships(&state, vault, relationships.clone()).await;
    assert!(write_result.is_ok(), "Write should succeed");

    // Read relationships back using read() with specific keys
    let key_alice_readme = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results = state.store.read(vault, &key_alice_readme, Revision(u64::MAX)).await;
    assert!(results.is_ok(), "Read should succeed");
    assert_eq!(results.unwrap().len(), 1, "Should find alice as viewer of readme");

    // Read bob as editor
    let key_bob_readme = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "editor".to_string(),
        subject: Some("user:bob".to_string()),
    };

    let results = state.store.read(vault, &key_bob_readme, Revision(u64::MAX)).await.unwrap();
    assert_eq!(results.len(), 1, "Should find bob as editor of readme");
}

/// Test: Vault isolation - same resources in different vaults
#[tokio::test]
async fn test_e2e_vault_isolation_same_resources() {
    let (state, vault_a, _account_a, vault_b, _account_b) = create_multi_vault_test_state();

    // Write same resource/relation/subject to both vaults
    let rel_a = create_test_relationship(vault_a, "doc:readme", "viewer", "user:alice");
    let rel_b = create_test_relationship(vault_b, "doc:readme", "viewer", "user:alice");

    write_test_relationships(&state, vault_a, vec![rel_a]).await.unwrap();
    write_test_relationships(&state, vault_b, vec![rel_b]).await.unwrap();

    // Read from vault A
    let key = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results_a = state.store.read(vault_a, &key, Revision(u64::MAX)).await.unwrap();
    let results_b = state.store.read(vault_b, &key, Revision(u64::MAX)).await.unwrap();

    // Each vault should only see its own relationship
    assert_eq!(results_a.len(), 1, "Vault A should have 1 relationship");
    assert_eq!(results_b.len(), 1, "Vault B should have 1 relationship");

    // Verify vault isolation
    assert_eq!(results_a[0].vault, vault_a, "Vault A relationship should have vault A ID");
    assert_eq!(results_b[0].vault, vault_b, "Vault B relationship should have vault B ID");

    // Both have same resource/relation/subject but different vaults
    assert_ne!(results_a[0].vault, results_b[0].vault, "Vaults must be different");
}

/// Test: Write → Delete → Verify deletion
#[tokio::test]
async fn test_e2e_write_then_delete() {
    let state = create_test_state();
    let vault = 22222222222222i64;

    // Write relationships
    let relationships = vec![
        create_test_relationship(vault, "doc:readme", "viewer", "user:alice"),
        create_test_relationship(vault, "doc:readme", "editor", "user:bob"),
    ];

    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Verify written
    let key_alice = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let before_delete = state.store.read(vault, &key_alice, Revision(u64::MAX)).await.unwrap();
    assert_eq!(before_delete.len(), 1, "Should have alice's relationship before delete");

    // Delete using delete_by_filter
    let delete_filter = infera_types::DeleteFilter {
        resource: Some("doc:readme".to_string()),
        relation: Some("viewer".to_string()),
        subject: Some("user:alice".to_string()),
    };

    let delete_result = state.store.delete_by_filter(vault, &delete_filter, None).await;
    assert!(delete_result.is_ok(), "Delete should succeed");

    // Verify deletion
    let after_delete = state.store.read(vault, &key_alice, Revision(u64::MAX)).await.unwrap();
    assert_eq!(after_delete.len(), 0, "Alice's relationship should be deleted");

    // Verify bob's relationship still exists
    let key_bob = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "editor".to_string(),
        subject: Some("user:bob".to_string()),
    };
    let bob_after = state.store.read(vault, &key_bob, Revision(u64::MAX)).await.unwrap();
    assert_eq!(bob_after.len(), 1, "Bob's relationship should remain");
}

/// Test: Revision-based consistency
#[tokio::test]
async fn test_e2e_revision_consistency() {
    let state = create_test_state();
    let vault = 33333333333333i64;

    // Write first batch
    let batch1 = vec![create_test_relationship(vault, "doc:v1", "viewer", "user:alice")];
    let rev1 = write_test_relationships(&state, vault, batch1).await.unwrap();
    assert!(rev1.0 > 0, "Revision should be positive");

    // Write second batch
    let batch2 = vec![create_test_relationship(vault, "doc:v2", "viewer", "user:bob")];
    let rev2 = write_test_relationships(&state, vault, batch2).await.unwrap();
    assert!(rev2.0 > rev1.0, "Second revision should be greater than first");

    // Read at different revisions
    let key_v1 = RelationshipKey {
        resource: "doc:v1".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let key_v2 = RelationshipKey {
        resource: "doc:v2".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:bob".to_string()),
    };

    // At revision 1, only v1 should exist
    let at_rev1_v1 = state.store.read(vault, &key_v1, rev1).await.unwrap();
    let at_rev1_v2 = state.store.read(vault, &key_v2, rev1).await.unwrap();
    assert_eq!(at_rev1_v1.len(), 1, "At revision 1, v1 should exist");
    assert_eq!(at_rev1_v2.len(), 0, "At revision 1, v2 should not exist yet");

    // At revision 2 (or latest), both should exist
    let at_latest_v1 = state.store.read(vault, &key_v1, Revision(u64::MAX)).await.unwrap();
    let at_latest_v2 = state.store.read(vault, &key_v2, Revision(u64::MAX)).await.unwrap();
    assert_eq!(at_latest_v1.len(), 1, "At latest, v1 should exist");
    assert_eq!(at_latest_v2.len(), 1, "At latest, v2 should exist");
}

/// Test: Bulk operations
#[tokio::test]
async fn test_e2e_bulk_write() {
    let state = create_test_state();
    let vault = 44444444444444i64;

    // Write many relationships in bulk
    let bulk_relationships: Vec<Relationship> = (0..50)
        .map(|i| create_test_relationship(vault, &format!("doc:{}", i), "viewer", "user:alice"))
        .collect();

    let write_result = write_test_relationships(&state, vault, bulk_relationships).await;
    assert!(write_result.is_ok(), "Bulk write should succeed");

    // Verify a few were written
    let key_0 = RelationshipKey {
        resource: "doc:0".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let result_0 = state.store.read(vault, &key_0, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_0.len(), 1, "doc:0 should exist");

    let key_49 = RelationshipKey {
        resource: "doc:49".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let result_49 = state.store.read(vault, &key_49, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_49.len(), 1, "doc:49 should exist");
}

/// Test: Independent writes to different vaults
#[tokio::test]
async fn test_e2e_independent_vault_operations() {
    let (state, vault_a, _account_a, vault_b, _account_b) = create_multi_vault_test_state();

    // Write to vault A
    let rels_a: Vec<Relationship> = (0..10)
        .map(|i| create_test_relationship(vault_a, &format!("doc:a{}", i), "viewer", "user:alice"))
        .collect();
    let result_a = write_test_relationships(&state, vault_a, rels_a).await;
    assert!(result_a.is_ok(), "Vault A write should succeed");

    // Write to vault B
    let rels_b: Vec<Relationship> = (0..10)
        .map(|i| create_test_relationship(vault_b, &format!("doc:b{}", i), "viewer", "user:bob"))
        .collect();
    let result_b = write_test_relationships(&state, vault_b, rels_b).await;
    assert!(result_b.is_ok(), "Vault B write should succeed");

    // Verify vault A has doc:a0 but not doc:b0
    let key_a0 = RelationshipKey {
        resource: "doc:a0".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let result_a0 = state.store.read(vault_a, &key_a0, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_a0.len(), 1, "Vault A should have doc:a0");

    let key_b0 = RelationshipKey {
        resource: "doc:b0".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:bob".to_string()),
    };
    let result_b0_in_a = state.store.read(vault_a, &key_b0, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_b0_in_a.len(), 0, "Vault A should NOT have doc:b0");

    // Verify vault B has doc:b0 but not doc:a0
    let result_b0 = state.store.read(vault_b, &key_b0, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_b0.len(), 1, "Vault B should have doc:b0");

    let result_a0_in_b = state.store.read(vault_b, &key_a0, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_a0_in_b.len(), 0, "Vault B should NOT have doc:a0");
}

/// Test: Empty vault operations
#[tokio::test]
async fn test_e2e_empty_vault_operations() {
    let state = create_test_state();
    let empty_vault = 55555555555555i64;

    // Read from empty vault
    let key = RelationshipKey {
        resource: "doc:nonexistent".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:nobody".to_string()),
    };

    let result = state.store.read(empty_vault, &key, Revision(u64::MAX)).await;
    assert!(result.is_ok(), "Read on empty vault should succeed");
    assert_eq!(result.unwrap().len(), 0, "Empty vault should return no relationships");

    // Delete from empty vault (should not error)
    let delete_filter = infera_types::DeleteFilter {
        resource: Some("nonexistent".to_string()),
        relation: None,
        subject: None,
    };
    let delete_result = state.store.delete_by_filter(empty_vault, &delete_filter, None).await;
    assert!(delete_result.is_ok(), "Delete on empty vault should succeed");
}
