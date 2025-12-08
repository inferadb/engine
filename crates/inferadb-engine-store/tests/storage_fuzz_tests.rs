//! Storage Layer Fuzzing Tests
//!
//! These tests use property-based testing to fuzz storage operations,
//! ensuring data integrity, crash resistance, and proper error handling.

use std::sync::Arc;

use inferadb_engine_store::{MemoryBackend, RelationshipStore};
use inferadb_engine_types::{Relationship, RelationshipKey, Revision};
use proptest::prelude::*;
// Test vault ID for all fuzz tests
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Fuzz write operations with arbitrary relationships
    #[test]
    fn fuzz_write_operations(relationships in prop::collection::vec(arb_relationship(), 1..100)) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Write should not panic, even with invalid data
            let result = store.write(test_vault_id(), relationships.clone()).await;

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
        resource in prop_oneof![
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
            let revision = store.get_revision(test_vault_id()).await.unwrap_or(Revision(0));

            // Create relationship key
            let key = RelationshipKey {
                resource,
                relation,
                subject: user_filter,
            };

            // Read should not panic
            let result = store.read(test_vault_id(), &key, revision).await;

            // Should return Ok (possibly empty results) or a clean error
            match result {
                Ok(relationships) => {
                    // Results should be valid
                    for relationship in relationships {
                        assert!(!relationship.resource.is_empty() || !relationship.relation.is_empty() || !relationship.subject.is_empty());
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
        resource in prop_oneof![
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

            // Create relationship key
            let key = RelationshipKey {
                resource,
                relation,
                subject: user_filter,
            };

            // Delete should not panic
            let result = store.delete(test_vault_id(), &key).await;

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
        batch1 in prop::collection::vec(arb_relationship(), 1..50),
        batch2 in prop::collection::vec(arb_relationship(), 1..50),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Spawn concurrent writes
            let store1 = store.clone();
            let store2 = store.clone();

            let handle1 = tokio::spawn(async move {
                store1.write(test_vault_id(), batch1).await
            });

            let handle2 = tokio::spawn(async move {
                store2.write(test_vault_id(), batch2).await
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
        resource in "[a-zA-Z0-9_:-]{1,100}",
        relation in "[a-z]{1,50}",
        revision_offset in 0u64..1000,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

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
                let key = RelationshipKey {
                    resource,
                    relation,
                    subject: None,
                };

                let result = store.read(test_vault_id(), &key, Revision(read_rev)).await;

                // Should not panic
                match result {
                    Ok(_relationships) => {
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

    /// Fuzz with duplicate relationships
    #[test]
    fn fuzz_duplicate_relationships(relationship in arb_relationship(), count in 1usize..100) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            // Create duplicates
            let relationships = vec![relationship; count];

            // Should handle duplicates gracefully
            let result = store.write(test_vault_id(), relationships).await;

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

            // Should not crash
            let result = store.write(test_vault_id(), vec![relationship]).await;

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
        Just("subject:*"),
        Just("*"),
        Just("subject:*:*"),
        Just("**"),
        Just("subject:a*"),
        Just("subject:*b"),
    ]) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            let relationship = Relationship {
                vault: test_vault_id(),
                resource: "obj:test".to_string(),
                relation: "viewer".to_string(),
                subject: pattern.to_string(),
            };

            // Wildcards should be handled correctly
            let result = store.write(test_vault_id(), vec![relationship]).await;

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
        valid_relationships in prop::collection::vec(
            (1usize..100, 1usize..50, 1usize..100).prop_map(|(o, r, u)| Relationship {
                vault: test_vault_id(),
                resource: format!("obj{}", o),
                relation: format!("rel{}", r),
                subject: format!("user{}", u),
            }),
            1..50,
        ),
        invalid_relationships in prop::collection::vec(arb_relationship(), 1..50),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());

            let mut all_relationships = valid_relationships;
            all_relationships.extend(invalid_relationships);

            // Mixed batch should not panic
            let result = store.write(test_vault_id(), all_relationships).await;

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
        let store = Arc::new(MemoryBackend::new());

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
        let store = Arc::new(MemoryBackend::new());

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
        let store = Arc::new(MemoryBackend::new());

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
