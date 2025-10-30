//! Storage Layer Fuzzing Tests
//!
//! These tests use property-based testing to fuzz storage operations,
//! ensuring data integrity, crash resistance, and proper error handling.

use infera_store::{MemoryBackend, Tuple, TupleStore};
use proptest::prelude::*;
use std::sync::Arc;

/// Generate arbitrary tuple data
fn arb_tuple() -> impl Strategy<Value = Tuple> {
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
            Just("'; DROP TABLE tuples; --".to_string()),
            Just("../../etc/passwd".to_string()),
        ],
        prop_oneof![
            "[a-z]{1,50}",
            Just(String::new()),
            "\\PC{1,30}",
        ],
        prop_oneof![
            "[a-zA-Z0-9_:-]{1,100}",
            Just("user:*".to_string()),
            Just(String::new()),
            "\\PC{1,50}",
        ],
    )
        .prop_map(|(object, relation, user)| Tuple {
            object,
            relation,
            user,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Fuzz write operations with arbitrary tuples
    #[test]
    fn fuzz_write_operations(tuples in prop::collection::vec(arb_tuple(), 1..100)) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Write should not panic, even with invalid data
            let result = store.write(tuples.clone()).await;

            // We expect either success or a clean error
            // Panics are not acceptable
            match result {
                Ok(revision) => {
                    // Revision should be monotonically increasing
                    assert!(revision.0 > 0, "Revision must be positive");
                }
                Err(_) => {
                    // Errors are acceptable for invalid input
                    // Just verify we didn't crash
                }
            }
        });
    }

    /// Fuzz read operations with arbitrary patterns
    #[test]
    fn fuzz_read_operations(
        object in prop_oneof![
            "[a-zA-Z0-9_:-]{1,100}",
            Just(String::new()),
            "\\PC{1,50}",
        ],
        relation in prop_oneof![
            "[a-z]{1,50}",
            Just(String::new()),
        ],
        user_filter in prop::option::of("[a-zA-Z0-9_:-]{1,100}"),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Get current revision
            let revision = store.get_revision().await.unwrap_or(infera_store::Revision(0));

            // Create tuple key
            let key = infera_store::TupleKey {
                object,
                relation,
                user: user_filter,
            };

            // Read should not panic
            let result = store.read(&key, revision).await;

            // Should return Ok (possibly empty results) or a clean error
            match result {
                Ok(tuples) => {
                    // Results should be valid
                    for tuple in tuples {
                        assert!(!tuple.object.is_empty() || !tuple.relation.is_empty() || !tuple.user.is_empty());
                    }
                }
                Err(_) => {
                    // Errors are acceptable for invalid patterns
                }
            }
        });
    }

    /// Fuzz delete operations
    #[test]
    fn fuzz_delete_operations(
        object in prop_oneof![
            "[a-zA-Z0-9_:-]{1,100}",
            Just(String::new()),
        ],
        relation in prop_oneof![
            "[a-z]{1,50}",
            Just(String::new()),
        ],
        user_filter in prop::option::of("[a-zA-Z0-9_:-]{1,100}"),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Create tuple key
            let key = infera_store::TupleKey {
                object,
                relation,
                user: user_filter,
            };

            // Delete should not panic
            let result = store.delete(&key).await;

            match result {
                Ok(revision) => {
                    assert!(revision.0 > 0);
                }
                Err(_) => {
                    // Errors acceptable
                }
            }
        });
    }

    /// Fuzz with concurrent writes
    #[test]
    fn fuzz_concurrent_writes(
        batch1 in prop::collection::vec(arb_tuple(), 1..50),
        batch2 in prop::collection::vec(arb_tuple(), 1..50),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Spawn concurrent writes
            let store1 = store.clone();
            let store2 = store.clone();

            let handle1 = tokio::spawn(async move {
                store1.write(batch1).await
            });

            let handle2 = tokio::spawn(async move {
                store2.write(batch2).await
            });

            // Both should complete without panicking
            let result1 = handle1.await;
            let result2 = handle2.await;

            // Tasks should not panic
            assert!(result1.is_ok(), "Task 1 panicked");
            assert!(result2.is_ok(), "Task 2 panicked");
        });
    }

    /// Fuzz revision-based reads
    #[test]
    fn fuzz_revision_reads(
        object in "[a-zA-Z0-9_:-]{1,100}",
        relation in "[a-z]{1,50}",
        revision_offset in 0u64..1000,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Write some data first
            let tuple = Tuple {
                object: object.clone(),
                relation: relation.clone(),
                user: "user:test".to_string(),
            };

            if let Ok(write_rev) = store.write(vec![tuple]).await {
                // Try reading at various revisions
                let read_rev = write_rev.0.saturating_sub(revision_offset);

                // Create tuple key for reading
                let key = infera_store::TupleKey {
                    object,
                    relation,
                    user: None,
                };

                let result = store.read(&key, infera_store::Revision(read_rev)).await;

                // Should not panic
                match result {
                    Ok(_tuples) => {
                        // Valid read
                    }
                    Err(_) => {
                        // Error acceptable for invalid revision
                    }
                }
            }
        });
    }

    /// Fuzz with extremely large batches
    #[test]
    fn fuzz_large_batches(size in 0usize..10000) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            let tuples: Vec<Tuple> = (0..size)
                .map(|i| Tuple {
                    object: format!("obj{}", i),
                    relation: "rel".to_string(),
                    user: format!("user{}", i),
                })
                .collect();

            // Large batch should not crash (though it might error on limits)
            let result = store.write(tuples).await;

            match result {
                Ok(rev) => {
                    assert!(rev.0 > 0);
                }
                Err(_) => {
                    // Size limits are acceptable
                }
            }
        });
    }

    /// Fuzz with duplicate tuples
    #[test]
    fn fuzz_duplicate_tuples(tuple in arb_tuple(), count in 1usize..100) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Create duplicates
            let tuples = vec![tuple; count];

            // Should handle duplicates gracefully
            let result = store.write(tuples).await;

            match result {
                Ok(_) => {
                    // Duplicates might be accepted or deduplicated
                }
                Err(_) => {
                    // Errors acceptable
                }
            }
        });
    }

    /// Fuzz with null bytes and control characters
    #[test]
    fn fuzz_control_characters(
        null_count in 0usize..10,
        control_count in 0usize..10,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            let mut object = String::from("obj");
            for _ in 0..null_count {
                object.push('\0');
            }
            for i in 0..control_count {
                object.push(char::from_u32(i as u32 + 1).unwrap_or('x'));
            }

            let tuple = Tuple {
                object,
                relation: "rel".to_string(),
                user: "user:test".to_string(),
            };

            // Should not crash
            let result = store.write(vec![tuple]).await;

            match result {
                Ok(_) => {}
                Err(_) => {
                    // Control characters might be rejected
                }
            }
        });
    }

    /// Fuzz wildcard user patterns
    #[test]
    fn fuzz_wildcard_patterns(pattern in prop_oneof![
        Just("user:*"),
        Just("*"),
        Just("user:*:*"),
        Just("**"),
        Just("user:a*"),
        Just("user:*b"),
    ]) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            let tuple = Tuple {
                object: "obj:test".to_string(),
                relation: "viewer".to_string(),
                user: pattern.to_string(),
            };

            // Wildcards should be handled correctly
            let result = store.write(vec![tuple]).await;

            match result {
                Ok(_) => {
                    // Some wildcards might be valid
                }
                Err(_) => {
                    // Some might be rejected
                }
            }
        });
    }

    /// Fuzz mixed valid and invalid operations
    #[test]
    fn fuzz_mixed_operations(
        valid_tuples in prop::collection::vec(
            (1usize..100, 1usize..50, 1usize..100).prop_map(|(o, r, u)| Tuple {
                object: format!("obj{}", o),
                relation: format!("rel{}", r),
                user: format!("user{}", u),
            }),
            1..50,
        ),
        invalid_tuples in prop::collection::vec(arb_tuple(), 1..50),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            let mut all_tuples = valid_tuples;
            all_tuples.extend(invalid_tuples);

            // Mixed batch should not panic
            let result = store.write(all_tuples).await;

            match result {
                Ok(_) => {
                    // Might accept some or all
                }
                Err(_) => {
                    // Might reject due to invalid entries
                }
            }
        });
    }
}

/// Integration tests for storage robustness
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_handles_empty_fields() {
        let store = Arc::new(MemoryBackend::new());

        // Empty fields
        let tuple = Tuple {
            object: "".to_string(),
            relation: "".to_string(),
            user: "".to_string(),
        };

        // Should not crash (may error)
        let _ = store.write(vec![tuple]).await;
    }

    #[tokio::test]
    async fn test_storage_handles_very_long_fields() {
        let store = Arc::new(MemoryBackend::new());

        // Very long fields
        let tuple = Tuple {
            object: "a".repeat(100000),
            relation: "b".repeat(100000),
            user: "c".repeat(100000),
        };

        // Should not crash (may error on size limits)
        let _ = store.write(vec![tuple]).await;
    }

    #[tokio::test]
    async fn test_storage_maintains_consistency_under_load() {
        let store = Arc::new(MemoryBackend::new());

        // Write many tuples concurrently
        let mut handles = vec![];

        for i in 0..100 {
            let store_clone = store.clone();
            handles.push(tokio::spawn(async move {
                let tuple = Tuple {
                    object: format!("obj{}", i),
                    relation: "rel".to_string(),
                    user: format!("user{}", i),
                };
                store_clone.write(vec![tuple]).await
            }));
        }

        // All should complete
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok(), "Task panicked");
        }

        // Data should be consistent
        let current_rev = store.get_revision().await.unwrap();
        assert!(current_rev.0 >= 100, "Should have at least 100 revisions");
    }

    #[tokio::test]
    async fn test_storage_recovers_from_errors() {
        let store = Arc::new(MemoryBackend::new());

        // Try to cause errors with invalid data
        let invalid_tuple = Tuple {
            object: "'; DROP TABLE tuples; --".to_string(),
            relation: "../../etc/passwd".to_string(),
            user: "<script>alert('xss')</script>".to_string(),
        };

        // Should handle gracefully
        let _ = store.write(vec![invalid_tuple]).await;

        // Storage should still be functional
        let valid_tuple = Tuple {
            object: "obj:test".to_string(),
            relation: "viewer".to_string(),
            user: "user:alice".to_string(),
        };

        let result = store.write(vec![valid_tuple]).await;
        assert!(result.is_ok(), "Storage should recover from errors");
    }
}
