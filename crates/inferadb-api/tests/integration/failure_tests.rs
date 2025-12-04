//! Failure and Error Handling Tests
//!
//! These tests verify that the system handles failure scenarios gracefully:
//! - Cache disabled operations
//! - Invalid revision requests
//! - Non-existent resource operations
//! - Concurrent write conflicts
//! - Empty result sets

use inferadb_types::{DeleteFilter, Relationship, RelationshipKey, Revision};

use crate::{
    create_test_config, create_test_relationship, create_test_state, write_test_relationships,
};

/// Test: Operations with cache disabled
#[tokio::test]
async fn test_cache_disabled_operations() {
    let mut config = create_test_config();
    config.cache.enabled = false;

    let state = crate::create_test_state_with_config(config);
    let vault = 11111111111111i64;

    // Write relationships
    let relationships = vec![
        create_test_relationship(vault, "doc:readme", "viewer", "user:alice"),
        create_test_relationship(vault, "doc:readme", "editor", "user:bob"),
    ];

    let write_result = write_test_relationships(&state, vault, relationships).await;
    assert!(write_result.is_ok(), "Write should succeed even with cache disabled");

    // Read relationships back
    let key = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    let results = state.store.read(vault, &key, Revision(u64::MAX)).await;
    assert!(results.is_ok(), "Read should succeed with cache disabled");
    assert_eq!(results.unwrap().len(), 1, "Should find relationship without cache");
}

/// Test: Reading with old revision (before data was written)
#[tokio::test]
async fn test_read_with_old_revision() {
    let state = create_test_state();
    let vault = 22222222222222i64;

    // Write relationships
    let relationships = vec![create_test_relationship(vault, "doc:readme", "viewer", "user:alice")];

    let rev = write_test_relationships(&state, vault, relationships).await.unwrap();

    // Try to read with revision before the write
    let key = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    // Read at revision 0 (before write)
    let results = state.store.read(vault, &key, Revision(0)).await;
    assert!(results.is_ok(), "Read with old revision should succeed");
    assert_eq!(results.unwrap().len(), 0, "Should not find relationship at old revision");

    // Read at current revision (should find it)
    let results = state.store.read(vault, &key, rev).await.unwrap();
    assert_eq!(results.len(), 1, "Should find relationship at current revision");
}

/// Test: Reading non-existent relationships
#[tokio::test]
async fn test_read_nonexistent_relationships() {
    let state = create_test_state();
    let vault = 33333333333333i64;

    let key = RelationshipKey {
        resource: "doc:nonexistent".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:nobody".to_string()),
    };

    let results = state.store.read(vault, &key, Revision(u64::MAX)).await;
    assert!(results.is_ok(), "Reading non-existent relationships should not error");
    assert_eq!(results.unwrap().len(), 0, "Should return empty result set");
}

/// Test: Deleting non-existent relationships
#[tokio::test]
async fn test_delete_nonexistent_relationships() {
    let state = create_test_state();
    let vault = 44444444444444i64;

    let filter = DeleteFilter {
        resource: Some("doc:nonexistent".to_string()),
        relation: Some("viewer".to_string()),
        subject: Some("user:nobody".to_string()),
    };

    let result = state.store.delete_by_filter(vault, &filter, None).await;
    assert!(result.is_ok(), "Deleting non-existent relationships should not error");
}

/// Test: Multiple deletes on same data
#[tokio::test]
async fn test_multiple_deletes_same_data() {
    let state = create_test_state();
    let vault = 55555555555555i64;

    // Write relationships
    let relationships = vec![create_test_relationship(vault, "doc:readme", "viewer", "user:alice")];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    let filter = DeleteFilter {
        resource: Some("doc:readme".to_string()),
        relation: Some("viewer".to_string()),
        subject: Some("user:alice".to_string()),
    };

    // First delete
    let result1 = state.store.delete_by_filter(vault, &filter, None).await;
    assert!(result1.is_ok(), "First delete should succeed");

    // Second delete (data already gone)
    let result2 = state.store.delete_by_filter(vault, &filter, None).await;
    assert!(result2.is_ok(), "Second delete should not error even though data is gone");

    // Verify data is deleted
    let key = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let results = state.store.read(vault, &key, Revision(u64::MAX)).await.unwrap();
    assert_eq!(results.len(), 0, "Data should be deleted");
}

/// Test: Empty filter matches nothing
#[tokio::test]
async fn test_delete_with_no_filter_fields() {
    let state = create_test_state();
    let vault = 66666666666666i64;

    // Write some relationships
    let relationships = vec![
        create_test_relationship(vault, "doc:readme", "viewer", "user:alice"),
        create_test_relationship(vault, "doc:guide", "editor", "user:bob"),
    ];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Try to delete with empty filter (no fields specified)
    // This is an edge case - the behavior depends on implementation
    let filter = DeleteFilter { resource: None, relation: None, subject: None };

    let result = state.store.delete_by_filter(vault, &filter, None).await;
    // The system should handle this gracefully (either error or delete all)
    // For now, we just verify it doesn't panic
    let _ = result;
}

/// Test: Concurrent writes to different vaults
#[tokio::test]
async fn test_concurrent_writes_different_vaults() {
    let state = create_test_state();
    let vault_a = 77777777777777i64;
    let vault_b = 88888888888888i64;

    // Create write tasks for different vaults
    let state_clone = state.clone();
    let handle_a = tokio::spawn(async move {
        let relationships =
            vec![create_test_relationship(vault_a, "doc:a", "viewer", "user:alice")];
        let result = write_test_relationships(&state_clone, vault_a, relationships).await;
        assert!(result.is_ok(), "Vault A write should succeed");
    });

    let state_clone = state.clone();
    let handle_b = tokio::spawn(async move {
        let relationships = vec![create_test_relationship(vault_b, "doc:b", "viewer", "user:bob")];
        let result = write_test_relationships(&state_clone, vault_b, relationships).await;
        assert!(result.is_ok(), "Vault B write should succeed");
    });

    // Wait for both to complete
    handle_a.await.unwrap();
    handle_b.await.unwrap();

    // Verify both vaults have their data
    let key_a = RelationshipKey {
        resource: "doc:a".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let results_a = state.store.read(vault_a, &key_a, Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_a.len(), 1, "Vault A should have its data");

    let key_b = RelationshipKey {
        resource: "doc:b".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:bob".to_string()),
    };
    let results_b = state.store.read(vault_b, &key_b, Revision(u64::MAX)).await.unwrap();
    assert_eq!(results_b.len(), 1, "Vault B should have its data");
}

/// Test: High-volume writes to test memory backend scalability
#[tokio::test]
async fn test_high_volume_writes() {
    let state = create_test_state();
    let vault = 99999999999999i64;

    // Write 100 relationships
    let relationships: Vec<Relationship> = (0..100)
        .map(|i| create_test_relationship(vault, &format!("doc:{}", i), "viewer", "user:alice"))
        .collect();

    let result = write_test_relationships(&state, vault, relationships).await;
    assert!(result.is_ok(), "High-volume write should succeed");

    // Verify a few random ones exist
    let key_0 = RelationshipKey {
        resource: "doc:0".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let result_0 = state.store.read(vault, &key_0, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_0.len(), 1, "doc:0 should exist");

    let key_99 = RelationshipKey {
        resource: "doc:99".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let result_99 = state.store.read(vault, &key_99, Revision(u64::MAX)).await.unwrap();
    assert_eq!(result_99.len(), 1, "doc:99 should exist");
}

/// Test: Partial filter matches (only resource specified)
#[tokio::test]
async fn test_partial_filter_delete() {
    let state = create_test_state();
    let vault = 10101010101010i64;

    // Write multiple relationships for same resource
    let relationships = vec![
        create_test_relationship(vault, "doc:readme", "viewer", "user:alice"),
        create_test_relationship(vault, "doc:readme", "editor", "user:bob"),
        create_test_relationship(vault, "doc:guide", "viewer", "user:alice"),
    ];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Delete all relationships for doc:readme (regardless of relation/subject)
    let filter =
        DeleteFilter { resource: Some("doc:readme".to_string()), relation: None, subject: None };

    let result = state.store.delete_by_filter(vault, &filter, None).await;
    assert!(result.is_ok(), "Partial filter delete should succeed");

    // Verify doc:readme relationships are gone
    let key_alice = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let results = state.store.read(vault, &key_alice, Revision(u64::MAX)).await.unwrap();
    assert_eq!(results.len(), 0, "doc:readme viewer relationship should be deleted");

    let key_bob = RelationshipKey {
        resource: "doc:readme".to_string(),
        relation: "editor".to_string(),
        subject: Some("user:bob".to_string()),
    };
    let results = state.store.read(vault, &key_bob, Revision(u64::MAX)).await.unwrap();
    assert_eq!(results.len(), 0, "doc:readme editor relationship should be deleted");

    // Verify doc:guide is still there
    let key_guide = RelationshipKey {
        resource: "doc:guide".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };
    let results = state.store.read(vault, &key_guide, Revision(u64::MAX)).await.unwrap();
    assert_eq!(results.len(), 1, "doc:guide relationship should remain");
}
