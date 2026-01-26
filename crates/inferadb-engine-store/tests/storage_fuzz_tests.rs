//! Storage Layer Fuzzing Tests
//!
//! These tests use property-based testing to fuzz storage operations,
//! ensuring data integrity, crash resistance, and proper error handling.
//!
//! # Smoke vs Fuzz Testing
//!
//! This module implements a two-tier testing approach:
//!
//! | Test Type | Prefix | Iterations | When Runs |
//! |-----------|--------|------------|-----------|
//! | Smoke | `smoke_*` | 5 (fixed seed) | Always (default CI) |
//! | Fuzz | `fuzz_*` | 50-500 | Only with `test-full` feature |
//!
//! **Smoke tests** provide fast feedback with deterministic inputs, ensuring
//! code paths are exercised without the overhead of full fuzzing. They use
//! fixed seeds for reproducibility.
//!
//! **Fuzz tests** provide comprehensive coverage with random inputs. They're
//! gated behind the `test-full` feature to avoid slowing down regular CI.
//!
//! # Running Tests
//!
//! ```bash
//! # Run smoke tests only (default)
//! cargo test --package inferadb-engine-store
//!
//! # Run both smoke and full fuzz tests
//! cargo test --package inferadb-engine-store --features test-full
//!
//! # Adjust fuzz case count via environment
//! PROPTEST_CASES=100 cargo test --package inferadb-engine-store --features test-full
//! ```
//!
//! # Runtime Reuse Pattern
//!
//! These tests use a single tokio runtime per test function, reused across all
//! proptest iterations. This is critical for performance - creating a new runtime
//! for each of 100 iterations would add ~5-7 seconds of overhead per test file.
//!
//! Instead of:
//! ```ignore
//! proptest! {
//!     #[test]
//!     fn my_test(input in strategy) {
//!         let rt = Runtime::new().unwrap();  // BAD: Created 100 times!
//!         rt.block_on(async { /* test */ });
//!     }
//! }
//! ```
//!
//! We use:
//! ```ignore
//! #[test]
//! fn my_test() {
//!     let rt = Runtime::new().expect("runtime");  // GOOD: Created once
//!     let mut runner = TestRunner::new(config());
//!     runner.run(&strategy, |input| {
//!         rt.block_on(async { /* test */ });
//!         Ok(())
//!     }).expect("proptest");
//! }
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use inferadb_engine_repository::EngineStorage;
use inferadb_engine_store::InferaStore;
#[cfg(feature = "test-full")]
use inferadb_engine_test_fixtures::proptest_config::proptest_config;
use inferadb_engine_test_fixtures::smoke::smoke_runner;
use inferadb_engine_types::{Relationship, RelationshipKey, Revision};
use inferadb_storage::MemoryBackend;
use proptest::prelude::*;
#[cfg(feature = "test-full")]
use proptest::test_runner::TestRunner;

/// Creates a new tokio runtime for test execution.
///
/// This should be called once per test function, not per iteration.
fn create_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to create tokio runtime")
}

/// Creates a new in-memory storage instance for testing.
fn create_store() -> Arc<dyn InferaStore> {
    Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build())
}

/// Test vault ID for all fuzz tests
fn test_vault_id() -> i64 {
    12345678901234i64
}

/// Generate arbitrary relationship data
fn arb_relationship() -> impl Strategy<Value = Relationship> {
    (
        prop_oneof![
            // Normal identifiers
            "[a-zA-Z0-9_:-]{1,100}",
            // Empty string
            Just(String::new()),
            // Very long strings
            prop::collection::vec(any::<char>(), 100..500).prop_map(|v| v.into_iter().collect()),
            // Special characters
            "[!@#$%^&*(){}\\[\\];:'\"<>,.?/|\\\\]{1,50}",
            // Unicode
            "\\PC{1,50}",
            // Potential injection
            Just("'; DROP TABLE relationships; --".to_string()),
            Just("../../etc/passwd".to_string()),
        ],
        prop_oneof!["[a-z]{1,50}", Just(String::new()), "\\PC{1,30}",],
        prop_oneof![
            "[a-zA-Z0-9_:-]{1,100}",
            Just("subject:*".to_string()),
            Just(String::new()),
            "\\PC{1,50}",
        ],
    )
        .prop_map(|(resource, relation, subject)| Relationship {
            vault: test_vault_id(),
            resource,
            relation,
            subject,
        })
}

// =============================================================================
// SMOKE TESTS
// =============================================================================
// These tests run by default with fixed seeds and 5 iterations.
// They verify the same code paths as fuzz tests but with minimal overhead.

/// Smoke test for write operations - verifies basic write path
#[test]
fn smoke_write_operations() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    runner
        .run(&prop::collection::vec(arb_relationship(), 1..100), |relationships| {
            rt.block_on(async {
                let store = create_store();
                let result = store.write(test_vault_id(), relationships).await;
                if let Ok(revision) = result {
                    prop_assert!(revision.0 > 0, "Revision must be positive");
                }
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for read operations - verifies basic read path
#[test]
fn smoke_read_operations() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = (
        prop_oneof!["[a-zA-Z0-9_:-]{1,100}", Just(String::new()), "\\PC{1,50}",],
        prop_oneof!["[a-z]{1,50}", Just(String::new()),],
        prop::option::of("[a-zA-Z0-9_:-]{1,100}"),
    );

    runner
        .run(&strategy, |(resource, relation, user_filter)| {
            rt.block_on(async {
                let store = create_store();
                let revision = store.get_revision(test_vault_id()).await.unwrap_or(Revision(0));
                let key = RelationshipKey { resource, relation, subject: user_filter };
                let result = store.read(test_vault_id(), &key, revision).await;
                if let Ok(relationships) = result {
                    for relationship in relationships {
                        prop_assert!(
                            !relationship.resource.is_empty()
                                || !relationship.relation.is_empty()
                                || !relationship.subject.is_empty()
                        );
                    }
                }
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for delete operations - verifies basic delete path
#[test]
fn smoke_delete_operations() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = (
        prop_oneof!["[a-zA-Z0-9_:-]{1,100}", Just(String::new()),],
        prop_oneof!["[a-z]{1,50}", Just(String::new()),],
        prop::option::of("[a-zA-Z0-9_:-]{1,100}"),
    );

    runner
        .run(&strategy, |(resource, relation, user_filter)| {
            rt.block_on(async {
                let store = create_store();
                let key = RelationshipKey { resource, relation, subject: user_filter };
                let result = store.delete(test_vault_id(), &key).await;
                if let Ok(revision) = result {
                    prop_assert!(revision.0 > 0);
                }
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for concurrent writes - verifies concurrent access path
#[test]
fn smoke_concurrent_writes() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = (
        prop::collection::vec(arb_relationship(), 1..50),
        prop::collection::vec(arb_relationship(), 1..50),
    );

    runner
        .run(&strategy, |(batch1, batch2)| {
            rt.block_on(async {
                let store = create_store();
                let store1 = store.clone();
                let store2 = store.clone();

                let handle1 =
                    tokio::spawn(async move { store1.write(test_vault_id(), batch1).await });
                let handle2 =
                    tokio::spawn(async move { store2.write(test_vault_id(), batch2).await });

                let result1 = handle1.await;
                let result2 = handle2.await;

                prop_assert!(result1.is_ok(), "Task 1 panicked");
                prop_assert!(result2.is_ok(), "Task 2 panicked");
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for revision-based reads - verifies revision query path
#[test]
fn smoke_revision_reads() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = ("[a-zA-Z0-9_:-]{1,100}", "[a-z]{1,50}", 0u64..1000);

    runner
        .run(&strategy, |(resource, relation, revision_offset)| {
            rt.block_on(async {
                let store = create_store();
                let relationship = Relationship {
                    vault: test_vault_id(),
                    resource: resource.clone(),
                    relation: relation.clone(),
                    subject: "user:test".to_string(),
                };

                if let Ok(write_rev) = store.write(test_vault_id(), vec![relationship]).await {
                    let read_rev = write_rev.0.saturating_sub(revision_offset);
                    let key = RelationshipKey { resource, relation, subject: None };
                    let _ = store.read(test_vault_id(), &key, Revision(read_rev)).await;
                }
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for large batches - verifies batch handling path
#[test]
fn smoke_large_batches() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    runner
        .run(&(0usize..10000), |size| {
            rt.block_on(async {
                let store = create_store();
                let relationships: Vec<Relationship> = (0..size)
                    .map(|i| Relationship {
                        vault: test_vault_id(),
                        resource: format!("obj{}", i),
                        relation: "rel".to_string(),
                        subject: format!("user{}", i),
                    })
                    .collect();

                let result = store.write(test_vault_id(), relationships).await;
                if let Ok(rev) = result {
                    prop_assert!(rev.0 > 0);
                }
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for duplicate relationships - verifies deduplication path
#[test]
fn smoke_duplicate_relationships() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = (arb_relationship(), 1usize..100);

    runner
        .run(&strategy, |(relationship, count)| {
            rt.block_on(async {
                let store = create_store();
                let relationships = vec![relationship; count];
                let _ = store.write(test_vault_id(), relationships).await;
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for control characters - verifies special char handling
#[test]
fn smoke_control_characters() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = (0usize..10, 0usize..10);

    runner
        .run(&strategy, |(null_count, control_count)| {
            rt.block_on(async {
                let store = create_store();
                let mut resource = String::from("obj");
                for _ in 0..null_count {
                    resource.push('\0');
                }
                for i in 0..control_count {
                    resource.push(char::from_u32(i as u32 + 1).unwrap_or('x'));
                }

                let relationship = Relationship {
                    vault: test_vault_id(),
                    resource,
                    relation: "rel".to_string(),
                    subject: "user:test".to_string(),
                };

                let _ = store.write(test_vault_id(), vec![relationship]).await;
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for wildcard patterns - verifies wildcard handling
#[test]
fn smoke_wildcard_patterns() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = prop_oneof![
        Just("subject:*"),
        Just("*"),
        Just("subject:*:*"),
        Just("**"),
        Just("subject:a*"),
        Just("subject:*b"),
    ];

    runner
        .run(&strategy, |pattern| {
            rt.block_on(async {
                let store = create_store();
                let relationship = Relationship {
                    vault: test_vault_id(),
                    resource: "obj:test".to_string(),
                    relation: "viewer".to_string(),
                    subject: pattern.to_string(),
                };

                let _ = store.write(test_vault_id(), vec![relationship]).await;
                Ok(())
            })
        })
        .expect("smoke test failed");
}

/// Smoke test for mixed operations - verifies mixed input handling
#[test]
fn smoke_mixed_operations() {
    let rt = create_runtime();
    let mut runner = smoke_runner();

    let strategy = (
        prop::collection::vec(
            (1usize..100, 1usize..50, 1usize..100).prop_map(|(o, r, u)| Relationship {
                vault: test_vault_id(),
                resource: format!("obj{}", o),
                relation: format!("rel{}", r),
                subject: format!("user{}", u),
            }),
            1..50,
        ),
        prop::collection::vec(arb_relationship(), 1..50),
    );

    runner
        .run(&strategy, |(valid_relationships, invalid_relationships)| {
            rt.block_on(async {
                let store = create_store();
                let mut all_relationships = valid_relationships;
                all_relationships.extend(invalid_relationships);
                let _ = store.write(test_vault_id(), all_relationships).await;
                Ok(())
            })
        })
        .expect("smoke test failed");
}

// =============================================================================
// FULL FUZZ TESTS
// =============================================================================
// These tests run only with `--features test-full` and use many more iterations
// with random seeds for comprehensive coverage.

/// Fuzz write operations with arbitrary relationships
#[test]
#[cfg(feature = "test-full")]
fn fuzz_write_operations() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    runner
        .run(&prop::collection::vec(arb_relationship(), 1..100), |relationships| {
            rt.block_on(async {
                let store = create_store();

                // Write should not panic, even with invalid data
                let result = store.write(test_vault_id(), relationships).await;

                // We expect either success or a clean error - panics are not acceptable
                if let Ok(revision) = result {
                    // Revision should be monotonically increasing
                    prop_assert!(revision.0 > 0, "Revision must be positive");
                }
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz read operations with arbitrary patterns
#[test]
#[cfg(feature = "test-full")]
fn fuzz_read_operations() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = (
        prop_oneof!["[a-zA-Z0-9_:-]{1,100}", Just(String::new()), "\\PC{1,50}",],
        prop_oneof!["[a-z]{1,50}", Just(String::new()),],
        prop::option::of("[a-zA-Z0-9_:-]{1,100}"),
    );

    runner
        .run(&strategy, |(resource, relation, user_filter)| {
            rt.block_on(async {
                let store = create_store();

                // Get current revision
                let revision = store.get_revision(test_vault_id()).await.unwrap_or(Revision(0));

                // Create relationship key
                let key = RelationshipKey { resource, relation, subject: user_filter };

                // Read should not panic
                let result = store.read(test_vault_id(), &key, revision).await;

                // Should return Ok (possibly empty results) or a clean error
                if let Ok(relationships) = result {
                    // Results should be valid
                    for relationship in relationships {
                        prop_assert!(
                            !relationship.resource.is_empty()
                                || !relationship.relation.is_empty()
                                || !relationship.subject.is_empty()
                        );
                    }
                }
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz delete operations
#[test]
#[cfg(feature = "test-full")]
fn fuzz_delete_operations() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = (
        prop_oneof!["[a-zA-Z0-9_:-]{1,100}", Just(String::new()),],
        prop_oneof!["[a-z]{1,50}", Just(String::new()),],
        prop::option::of("[a-zA-Z0-9_:-]{1,100}"),
    );

    runner
        .run(&strategy, |(resource, relation, user_filter)| {
            rt.block_on(async {
                let store = create_store();

                // Create relationship key
                let key = RelationshipKey { resource, relation, subject: user_filter };

                // Delete should not panic
                let result = store.delete(test_vault_id(), &key).await;

                if let Ok(revision) = result {
                    prop_assert!(revision.0 > 0);
                }
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz with concurrent writes
#[test]
#[cfg(feature = "test-full")]
fn fuzz_concurrent_writes() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = (
        prop::collection::vec(arb_relationship(), 1..50),
        prop::collection::vec(arb_relationship(), 1..50),
    );

    runner
        .run(&strategy, |(batch1, batch2)| {
            rt.block_on(async {
                let store = create_store();

                // Spawn concurrent writes
                let store1 = store.clone();
                let store2 = store.clone();

                let handle1 =
                    tokio::spawn(async move { store1.write(test_vault_id(), batch1).await });

                let handle2 =
                    tokio::spawn(async move { store2.write(test_vault_id(), batch2).await });

                // Both should complete without panicking
                let result1 = handle1.await;
                let result2 = handle2.await;

                // Tasks should not panic
                prop_assert!(result1.is_ok(), "Task 1 panicked");
                prop_assert!(result2.is_ok(), "Task 2 panicked");
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz revision-based reads
#[test]
#[cfg(feature = "test-full")]
fn fuzz_revision_reads() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = ("[a-zA-Z0-9_:-]{1,100}", "[a-z]{1,50}", 0u64..1000);

    runner
        .run(&strategy, |(resource, relation, revision_offset)| {
            rt.block_on(async {
                let store = create_store();

                // Write some data first
                let relationship = Relationship {
                    vault: test_vault_id(),
                    resource: resource.clone(),
                    relation: relation.clone(),
                    subject: "user:test".to_string(),
                };

                if let Ok(write_rev) = store.write(test_vault_id(), vec![relationship]).await {
                    // Try reading at various revisions
                    let read_rev = write_rev.0.saturating_sub(revision_offset);

                    // Create relationship key for reading
                    let key = RelationshipKey { resource, relation, subject: None };

                    // Should not panic - errors are acceptable for invalid revision
                    let _ = store.read(test_vault_id(), &key, Revision(read_rev)).await;
                }
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz with extremely large batches
#[test]
#[cfg(feature = "test-full")]
fn fuzz_large_batches() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    runner
        .run(&(0usize..10000), |size| {
            rt.block_on(async {
                let store = create_store();

                let relationships: Vec<Relationship> = (0..size)
                    .map(|i| Relationship {
                        vault: test_vault_id(),
                        resource: format!("obj{}", i),
                        relation: "rel".to_string(),
                        subject: format!("user{}", i),
                    })
                    .collect();

                // Large batch should not crash (though it might error on limits)
                let result = store.write(test_vault_id(), relationships).await;

                if let Ok(rev) = result {
                    prop_assert!(rev.0 > 0);
                }
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz with duplicate relationships
#[test]
#[cfg(feature = "test-full")]
fn fuzz_duplicate_relationships() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = (arb_relationship(), 1usize..100);

    runner
        .run(&strategy, |(relationship, count)| {
            rt.block_on(async {
                let store = create_store();

                // Create duplicates - should handle duplicates gracefully
                let relationships = vec![relationship; count];
                let _ = store.write(test_vault_id(), relationships).await;
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz with null bytes and control characters
#[test]
#[cfg(feature = "test-full")]
fn fuzz_control_characters() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = (0usize..10, 0usize..10);

    runner
        .run(&strategy, |(null_count, control_count)| {
            rt.block_on(async {
                let store = create_store();

                let mut resource = String::from("obj");
                for _ in 0..null_count {
                    resource.push('\0');
                }
                for i in 0..control_count {
                    resource.push(char::from_u32(i as u32 + 1).unwrap_or('x'));
                }

                let relationship = Relationship {
                    vault: test_vault_id(),
                    resource,
                    relation: "rel".to_string(),
                    subject: "user:test".to_string(),
                };

                // Should not crash - control characters might be rejected
                let _ = store.write(test_vault_id(), vec![relationship]).await;
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz wildcard user patterns
#[test]
#[cfg(feature = "test-full")]
fn fuzz_wildcard_patterns() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = prop_oneof![
        Just("subject:*"),
        Just("*"),
        Just("subject:*:*"),
        Just("**"),
        Just("subject:a*"),
        Just("subject:*b"),
    ];

    runner
        .run(&strategy, |pattern| {
            rt.block_on(async {
                let store = create_store();

                let relationship = Relationship {
                    vault: test_vault_id(),
                    resource: "obj:test".to_string(),
                    relation: "viewer".to_string(),
                    subject: pattern.to_string(),
                };

                // Wildcards should be handled correctly - some might be valid, some rejected
                let _ = store.write(test_vault_id(), vec![relationship]).await;
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Fuzz mixed valid and invalid operations
#[test]
#[cfg(feature = "test-full")]
fn fuzz_mixed_operations() {
    let rt = create_runtime();
    let mut runner = TestRunner::new(proptest_config());

    let strategy = (
        prop::collection::vec(
            (1usize..100, 1usize..50, 1usize..100).prop_map(|(o, r, u)| Relationship {
                vault: test_vault_id(),
                resource: format!("obj{}", o),
                relation: format!("rel{}", r),
                subject: format!("user{}", u),
            }),
            1..50,
        ),
        prop::collection::vec(arb_relationship(), 1..50),
    );

    runner
        .run(&strategy, |(valid_relationships, invalid_relationships)| {
            rt.block_on(async {
                let store = create_store();

                let mut all_relationships = valid_relationships;
                all_relationships.extend(invalid_relationships);

                // Mixed batch should not panic
                let _ = store.write(test_vault_id(), all_relationships).await;
                Ok(())
            })
        })
        .expect("proptest failed");
}

/// Integration tests for storage robustness
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_handles_empty_fields() {
        let store = create_store();

        // Empty fields
        let relationship = Relationship {
            vault: test_vault_id(),
            resource: "".to_string(),
            relation: "".to_string(),
            subject: "".to_string(),
        };

        // Should not crash (may error)
        let _ = store.write(test_vault_id(), vec![relationship]).await;
    }

    #[tokio::test]
    async fn test_storage_handles_very_long_fields() {
        let store = create_store();

        // Very long fields
        let relationship = Relationship {
            vault: test_vault_id(),
            resource: "a".repeat(100000),
            relation: "b".repeat(100000),
            subject: "c".repeat(100000),
        };

        // Should not crash (may error on size limits)
        let _ = store.write(test_vault_id(), vec![relationship]).await;
    }

    #[tokio::test]
    async fn test_storage_maintains_consistency_under_load() {
        let store = create_store();

        // Write many relationships concurrently
        let mut handles = vec![];

        for i in 0..100 {
            let store_clone = store.clone();
            handles.push(tokio::spawn(async move {
                let relationship = Relationship {
                    vault: test_vault_id(),
                    resource: format!("obj{}", i),
                    relation: "rel".to_string(),
                    subject: format!("user{}", i),
                };
                store_clone.write(test_vault_id(), vec![relationship]).await
            }));
        }

        // All should complete
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok(), "Task panicked");
        }

        // Data should be consistent
        let current_rev = store.get_revision(test_vault_id()).await.unwrap();
        assert!(current_rev.0 >= 100, "Should have at least 100 revisions");
    }

    #[tokio::test]
    async fn test_storage_recovers_from_errors() {
        let store = create_store();

        // Try to cause errors with invalid data
        let invalid_relationship = Relationship {
            vault: test_vault_id(),
            resource: "'; DROP TABLE relationships; --".to_string(),
            relation: "../../etc/passwd".to_string(),
            subject: "<script>alert('xss')</script>".to_string(),
        };

        // Should handle gracefully
        let _ = store.write(test_vault_id(), vec![invalid_relationship]).await;

        // Storage should still be functional
        let valid_relationship = Relationship {
            vault: test_vault_id(),
            resource: "obj:test".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let result = store.write(test_vault_id(), vec![valid_relationship]).await;
        assert!(result.is_ok(), "Storage should recover from errors");
    }
}
