//! Consistency and Concurrency Integration Tests
//!
//! These tests verify that the system maintains consistency under various
//! concurrent access patterns.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::sync::Arc;

use inferadb_engine_core::{
    Evaluator,
    ipl::{RelationDef, RelationExpr, Schema, TypeDef},
};
use inferadb_engine_repository::EngineStorage;
use inferadb_engine_store::RelationshipStore;
use inferadb_engine_types::{Decision, EvaluateRequest, Relationship, RelationshipKey};
use inferadb_storage::MemoryBackend;
use tokio::task::JoinSet;

mod common;
use common::{TestFixture, relationship};

/// Create a simple schema for testing
fn create_simple_schema() -> Schema {
    Schema::new(vec![TypeDef::new(
        "document".to_string(),
        vec![
            RelationDef::new("viewer".to_string(), Some(RelationExpr::This)),
            RelationDef::new("editor".to_string(), Some(RelationExpr::This)),
        ],
    )])
}

// Write-then-Read Consistency Tests
//

#[tokio::test]
async fn test_write_then_read_same_client() {
    let fixture = TestFixture::new(create_simple_schema());

    // Write a relationship
    fixture
        .write_relationships(vec![relationship("document:doc1", "viewer", "user:alice")])
        .await
        .expect("Failed to write relationship");

    // Immediately read it - should see the write
    fixture.assert_allowed("user:alice", "document:doc1", "viewer").await;
}

#[tokio::test]
async fn test_write_then_read_different_evaluators() {
    let schema = create_simple_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Create two evaluators sharing the same store
    let _evaluator1 = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema.clone()),
        None,
        0i64,
    );

    let evaluator2 =
        Evaluator::new(store.clone() as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64);

    // Write through the store
    store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    // Read with evaluator2 - should see the write
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:doc1".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision = evaluator2.check(request).await.expect("Check failed");
    assert_eq!(decision, Decision::Allow);
}

#[tokio::test]
async fn test_delete_then_read() {
    let fixture = TestFixture::new(create_simple_schema());

    // Write a relationship
    fixture
        .write_relationships(vec![relationship("document:doc1", "viewer", "user:alice")])
        .await
        .expect("Failed to write");

    // Verify it exists
    fixture.assert_allowed("user:alice", "document:doc1", "viewer").await;

    // Delete the relationship
    let key = RelationshipKey {
        resource: "document:doc1".to_string(),
        relation: "viewer".to_string(),
        subject: Some("user:alice".to_string()),
    };

    fixture.store.delete(0i64, &key).await.expect("Failed to delete");

    // Should no longer have access
    fixture.assert_denied("user:alice", "document:doc1", "viewer").await;
}

// Revision Consistency Tests
//

#[tokio::test]
async fn test_revision_monotonicity() {
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Write and get revision
    let rev1 = store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    // Write again
    let rev2 = store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc2".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    // Revisions should be strictly increasing
    assert!(rev2 > rev1, "Revision should increase after each write");
}

#[tokio::test]
async fn test_write_returns_new_revision() {
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Each write should return a new revision
    let rev1 = store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    let rev2 = store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc2".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    let rev3 = store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc3".to_string(),
                relation: "viewer".to_string(),
                subject: "user:charlie".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    assert!(rev1.0 > 0);
    assert!(rev2 > rev1);
    assert!(rev3 > rev2);
}

// Concurrent Operations Tests
//

#[tokio::test]
async fn test_evaluator_concurrent_reads() {
    let schema = create_simple_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Write initial data
    store
        .write(
            0i64,
            vec![
                Relationship {
                    resource: "document:doc1".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                },
                Relationship {
                    resource: "document:doc2".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:bob".to_string(),
                    vault: 0i64,
                },
            ],
        )
        .await
        .expect("Failed to write");

    // Spawn multiple concurrent reads with separate evaluators
    let mut set = JoinSet::new();
    for i in 0..10 {
        let store_clone = store.clone();
        let schema_clone = Arc::new(schema.clone());
        set.spawn(async move {
            let evaluator =
                Evaluator::new(store_clone as Arc<dyn RelationshipStore>, schema_clone, None, 0i64);

            let request = EvaluateRequest {
                subject: if i % 2 == 0 { "user:alice".to_string() } else { "user:bob".to_string() },
                resource: if i % 2 == 0 {
                    "document:doc1".to_string()
                } else {
                    "document:doc2".to_string()
                },
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            evaluator.check(request).await
        });
    }

    // All reads should succeed
    while let Some(result) = set.join_next().await {
        let decision = result.expect("Task panicked").expect("Check failed");
        assert_eq!(decision, Decision::Allow);
    }
}

#[tokio::test]
async fn test_evaluator_concurrent_writes() {
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Spawn multiple concurrent writes
    let mut set = JoinSet::new();
    for i in 0..10 {
        let store_clone = store.clone();
        set.spawn(async move {
            store_clone
                .write(
                    0i64,
                    vec![Relationship {
                        resource: format!("document:doc{}", i),
                        relation: "viewer".to_string(),
                        subject: format!("subject:user{}", i),
                        vault: 0i64,
                    }],
                )
                .await
        });
    }

    // All writes should succeed
    let mut revisions = Vec::new();
    while let Some(result) = set.join_next().await {
        let rev = result.expect("Task panicked").expect("Write failed");
        revisions.push(rev);
    }

    // All revisions should be unique
    revisions.sort();
    revisions.dedup();
    assert_eq!(revisions.len(), 10, "All writes should have unique revisions");
}

#[tokio::test]
async fn test_concurrent_write_and_read() {
    let schema = create_simple_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Start concurrent writes
    let mut write_set = JoinSet::new();
    for i in 0..5 {
        let store_clone = store.clone();
        write_set.spawn(async move {
            store_clone
                .write(
                    0i64,
                    vec![Relationship {
                        resource: format!("document:doc{}", i),
                        relation: "viewer".to_string(),
                        subject: format!("subject:writer{}", i),
                        vault: 0i64,
                    }],
                )
                .await
        });
    }

    // Start concurrent reads (checking documents that may or may not exist yet)
    let mut read_set = JoinSet::new();
    for i in 0..5 {
        let store_clone = store.clone();
        let schema_clone = Arc::new(schema.clone());
        read_set.spawn(async move {
            let evaluator =
                Evaluator::new(store_clone as Arc<dyn RelationshipStore>, schema_clone, None, 0i64);

            let request = EvaluateRequest {
                subject: format!("subject:writer{}", i),
                resource: format!("document:doc{}", i),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            // May succeed or fail depending on race
            evaluator.check(request).await
        });
    }

    // All operations should complete without panicking
    while let Some(result) = write_set.join_next().await {
        let _ = result.expect("Write task should not panic");
    }

    while let Some(result) = read_set.join_next().await {
        let _ = result.expect("Read task should not panic");
        // Note: Individual read operations may fail (reads of not-yet-written data)
        // but they should not panic or corrupt state
    }
}

#[tokio::test]
async fn test_concurrent_write_delete() {
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Write initial data
    for i in 0..5 {
        store
            .write(
                0i64,
                vec![Relationship {
                    resource: format!("document:doc{}", i),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                }],
            )
            .await
            .expect("Failed to write");
    }

    // Concurrently write and delete
    let mut set = JoinSet::new();

    // Add more relationships
    for i in 5..10 {
        let store_clone = store.clone();
        set.spawn(async move {
            store_clone
                .write(
                    0i64,
                    vec![Relationship {
                        resource: format!("document:doc{}", i),
                        relation: "viewer".to_string(),
                        subject: "user:alice".to_string(),
                        vault: 0i64,
                    }],
                )
                .await
        });
    }

    // Delete some relationships
    for i in 0..3 {
        let store_clone = store.clone();
        set.spawn(async move {
            let key = RelationshipKey {
                resource: format!("document:doc{}", i),
                relation: "viewer".to_string(),
                subject: Some("user:alice".to_string()),
            };
            store_clone.delete(0i64, &key).await
        });
    }

    // All operations should succeed
    while let Some(result) = set.join_next().await {
        result.expect("Task panicked").expect("Operation failed");
    }
}

#[tokio::test]
async fn test_read_your_own_writes() {
    let schema = create_simple_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Each task writes and immediately reads its own data
    let mut set = JoinSet::new();

    for i in 0..10 {
        let store_clone = store.clone();
        let schema_clone = Arc::new(schema.clone());

        set.spawn(async move {
            // Write
            store_clone
                .write(
                    0i64,
                    vec![Relationship {
                        resource: format!("document:doc{}", i),
                        relation: "viewer".to_string(),
                        subject: format!("subject:user{}", i),
                        vault: 0i64,
                    }],
                )
                .await
                .expect("Write failed");

            // Immediately read what we just wrote
            let evaluator =
                Evaluator::new(store_clone as Arc<dyn RelationshipStore>, schema_clone, None, 0i64);

            let request = EvaluateRequest {
                subject: format!("subject:user{}", i),
                resource: format!("document:doc{}", i),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            evaluator.check(request).await
        });
    }

    // All tasks should see their own writes
    while let Some(result) = set.join_next().await {
        let decision = result.expect("Task panicked").expect("Check failed");
        assert_eq!(decision, Decision::Allow, "Should see own writes");
    }
}

// Replication Consistency Tests
// (These tests verify basic consistency properties that replication should maintain)
//

#[tokio::test]
async fn test_eventual_consistency_simulation() {
    // Simulate eventual consistency by having multiple stores
    // that eventually converge
    let store1 = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
    let store2 = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Write to store1
    let relationships = vec![
        Relationship {
            resource: "document:doc1".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "document:doc2".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];

    store1.write(0i64, relationships.clone()).await.expect("Failed to write to store1");

    // Replicate to store2
    store2.write(0i64, relationships).await.expect("Failed to replicate to store2");

    // Both stores should now have the same revisions
    let rev1 = store1.write(0i64, vec![]).await.expect("Failed to get revision from store1");
    let rev2 = store2.write(0i64, vec![]).await.expect("Failed to get revision from store2");

    // After replication, both should be in sync (or store2 >= store1)
    assert!(rev2 >= rev1, "Replicated store should have caught up");
}

#[tokio::test]
async fn test_conflicting_writes_both_preserved() {
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Two separate writes for the same document but different users
    store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:doc1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    // Both users should have access (both relationships should exist)
    let schema = Arc::new(create_simple_schema());
    let evaluator = Evaluator::new(store.clone() as Arc<dyn RelationshipStore>, schema, None, 0i64);

    let alice_req = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:doc1".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let bob_req = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "document:doc1".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    assert_eq!(evaluator.check(alice_req).await.expect("Check failed"), Decision::Allow);
    assert_eq!(evaluator.check(bob_req).await.expect("Check failed"), Decision::Allow);
}

#[tokio::test]
async fn test_cross_region_consistency() {
    // Simulate cross-region consistency by using multiple stores
    let region_a = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
    let region_b = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Write in region A
    let relationship = Relationship {
        resource: "document:global1".to_string(),
        relation: "viewer".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    };

    region_a.write(0i64, vec![relationship.clone()]).await.expect("Failed to write in region A");

    // Simulate replication to region B
    region_b.write(0i64, vec![relationship]).await.expect("Failed to replicate to region B");

    // Both regions should have consistent views
    let schema = Arc::new(create_simple_schema());

    let eval_a = Evaluator::new(region_a as Arc<dyn RelationshipStore>, schema.clone(), None, 0i64);
    let eval_b = Evaluator::new(region_b as Arc<dyn RelationshipStore>, schema, None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:global1".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision_a = eval_a.check(request.clone()).await.expect("Check failed in region A");
    let decision_b = eval_b.check(request).await.expect("Check failed in region B");

    assert_eq!(decision_a, Decision::Allow);
    assert_eq!(decision_b, Decision::Allow);
    assert_eq!(decision_a, decision_b, "Both regions should agree");
}
