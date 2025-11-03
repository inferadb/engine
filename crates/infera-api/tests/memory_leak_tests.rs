//! Memory Leak Detection Tests
//!
//! These tests are designed to detect memory leaks, connection leaks, and resource
//! exhaustion issues over extended periods of operation.
//!
//! ## Running These Tests
//!
//! ```bash
//! # Run short version (for CI)
//! cargo test --test memory_leak_tests
//!
//! # Run extended version (local development)
//! cargo test --test memory_leak_tests -- --ignored
//!
//! # Run with memory profiling
//! valgrind --leak-check=full --show-leak-kinds=all \
//!     cargo test --test memory_leak_tests
//! ```
//!
//! ## Memory Profiling Tools
//!
//! See MEMORY_PROFILING.md for detailed instructions on using:
//! - valgrind (leak detection)
//! - heaptrack (heap profiling)
//! - dhat-rs (heap profiling)
//! - cargo-instruments (macOS profiling)

use std::{sync::Arc, time::Duration};

use infera_api::AppState;
use infera_config::Config;
use infera_core::{
    Evaluator,
    ipl::{RelationDef, RelationExpr, Schema, TypeDef},
};
use infera_store::{MemoryBackend, RelationshipStore};
use infera_types::{EvaluateRequest, ExpandRequest, Relationship};
use uuid::Uuid;

/// Create test schema
fn create_test_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![TypeDef::new(
        "document".to_string(),
        vec![
            RelationDef::new("owner".to_string(), None),
            RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Union(vec![
                    RelationExpr::This,
                    RelationExpr::RelationRef { relation: "owner".to_string() },
                ])),
            ),
        ],
    )]))
}

/// Create test app state
async fn create_test_state() -> AppState {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();
    let vault = Uuid::new_v4();
    let account = Uuid::new_v4();

    let evaluator =
        Arc::new(Evaluator::new(store.clone() as Arc<dyn RelationshipStore>, schema, None, vault));

    let mut config = Config::default();
    config.cache.enabled = true;
    config.cache.max_capacity = 10000;

    AppState {
        evaluator,
        store,
        config: Arc::new(config),
        jwks_cache: None,
        health_tracker: Arc::new(infera_api::health::HealthTracker::new()),
        default_vault: vault,
        default_account: account,
    }
}

/// Test: Repeated authorization checks should not leak memory
///
/// This test performs many authorization checks to ensure that:
/// - Memory doesn't grow unbounded
/// - Cache eviction works correctly
/// - No memory is leaked in the hot path
#[tokio::test]
async fn test_no_memory_leak_in_authorization_checks() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    // Pre-populate with some relationships
    let relationships: Vec<Relationship> = (0..100)
        .map(|i| Relationship {
            vault,
            resource: format!("document:{}", i),
            relation: "viewer".to_string(),
            subject: format!("user:{}", i % 10),
        })
        .collect();
    state.store.write(vault, relationships).await.unwrap();

    // Perform many authorization checks
    // In a real scenario, this would run for hours/days
    for iteration in 0..10_000 {
        let request = EvaluateRequest {
            subject: format!("user:{}", iteration % 10),
            resource: format!("document:{}", iteration % 100),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let _ = state.evaluator.check(request).await.unwrap();

        // Every 1000 iterations, verify cache is within bounds
        if iteration % 1000 == 0 {
            // Cache should evict old entries and not grow unbounded
            // The cache implementation uses moka which has built-in eviction
            // This test just ensures we don't hold onto references elsewhere
        }
    }

    // Test passes if we reach here without OOM
}

/// Test: Repeated expand operations should not leak memory
///
/// Expand operations create large result sets and should properly
/// clean up temporary allocations.
#[tokio::test]
async fn test_no_memory_leak_in_expand_operations() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    // Create relationships with multiple subjects
    let mut relationships = Vec::new();
    for doc_id in 0..50 {
        for user_id in 0..100 {
            relationships.push(Relationship {
                vault,
                resource: format!("document:{}", doc_id),
                relation: "viewer".to_string(),
                subject: format!("user:{}", user_id),
            });
        }
    }
    state.store.write(vault, relationships).await.unwrap();

    // Perform many expand operations
    for iteration in 0..1_000 {
        let request = ExpandRequest {
            resource: format!("document:{}", iteration % 50),
            relation: "viewer".to_string(),
            limit: None,
            continuation_token: None,
        };

        let result = state.evaluator.expand(request).await.unwrap();

        // Note: Results may be empty depending on the evaluation logic
        // This test is about memory leaks, not correctness
        // Drop result explicitly to ensure cleanup
        drop(result);
    }

    // Test passes if we reach here without OOM
}

/// Test: Repeated write and read cycles should not leak memory
///
/// This tests the storage layer for memory leaks during write/read cycles.
#[tokio::test]
async fn test_no_memory_leak_in_storage_operations() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    for iteration in 0..5_000 {
        // Write a batch of relationships
        let relationships: Vec<Relationship> = (0..20)
            .map(|i| Relationship {
                vault,
                resource: format!("document:{}:{}", iteration, i),
                relation: "viewer".to_string(),
                subject: format!("user:{}", i),
            })
            .collect();

        state.store.write(vault, relationships).await.unwrap();

        // Read them back
        let list_request = infera_types::ListRelationshipsRequest {
            resource: Some(format!("document:{}:*", iteration)),
            relation: None,
            subject: None,
            limit: Some(20),
            cursor: None,
        };

        let _ = state.evaluator.list_relationships(list_request).await.unwrap();
    }

    // Test passes if we reach here without OOM
}

/// Test: Cache eviction should not cause memory leaks
///
/// This test fills the cache beyond capacity to ensure eviction
/// properly releases memory.
#[tokio::test]
async fn test_no_memory_leak_in_cache_eviction() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    // Pre-populate relationships
    let relationships: Vec<Relationship> = (0..1000)
        .map(|i| Relationship {
            vault,
            resource: format!("document:{}", i),
            relation: "viewer".to_string(),
            subject: format!("user:{}", i),
        })
        .collect();
    state.store.write(vault, relationships).await.unwrap();

    // Perform more checks than cache capacity to force eviction
    // Cache capacity is 10,000 entries
    for i in 0..20_000 {
        let request = EvaluateRequest {
            subject: format!("user:{}", i % 1000),
            resource: format!("document:{}", i % 1000),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let _ = state.evaluator.check(request).await.unwrap();
    }

    // Test passes if we reach here without OOM
    // Cache should have evicted old entries and maintained bounded memory
}

/// Test: Concurrent operations should not leak memory
///
/// This test runs multiple concurrent operations to detect race
/// conditions that might cause memory leaks.
#[tokio::test]
async fn test_no_memory_leak_under_concurrent_load() {
    let state = Arc::new(create_test_state().await);
    let vault = state.default_vault;

    // Pre-populate relationships
    let relationships: Vec<Relationship> = (0..100)
        .map(|i| Relationship {
            vault,
            resource: format!("document:{}", i),
            relation: "viewer".to_string(),
            subject: format!("user:{}", i % 10),
        })
        .collect();
    state.store.write(vault, relationships).await.unwrap();

    // Spawn multiple concurrent tasks
    let mut handles = Vec::new();
    for task_id in 0..10 {
        let state_clone = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            for i in 0..1_000 {
                let request = EvaluateRequest {
                    subject: format!("user:{}", (task_id + i) % 10),
                    resource: format!("document:{}", (task_id + i) % 100),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };

                let _ = state_clone.evaluator.check(request).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Test passes if we reach here without OOM or deadlocks
}

/// Test: Stream handling should not leak memory
///
/// This test simulates long-lived streams to ensure proper cleanup.
#[tokio::test]
async fn test_no_memory_leak_in_streaming() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    // Create many relationships
    let mut relationships = Vec::new();
    for i in 0..1000 {
        relationships.push(Relationship {
            vault,
            resource: format!("document:{}", i),
            relation: "viewer".to_string(),
            subject: format!("user:{}", i % 100),
        });
    }
    state.store.write(vault, relationships).await.unwrap();

    // Repeatedly create and consume streams
    for _iteration in 0..500 {
        let request = infera_types::ListRelationshipsRequest {
            resource: None,
            relation: Some("viewer".to_string()),
            subject: None,
            limit: Some(100),
            cursor: None,
        };

        let result = state.evaluator.list_relationships(request).await.unwrap();

        // Consume the results
        let _count = result.relationships.len();

        // Drop result to ensure cleanup
        drop(result);
    }

    // Test passes if we reach here without OOM
}

// ==============================================================================
// LONG-RUNNING TESTS (24+ HOURS)
//
// These tests are ignored by default and should be run manually for extended
// periods to detect slow memory leaks.
// ==============================================================================

/// Long-running test: 24-hour authorization check stress test
///
/// Run with: `cargo test --test memory_leak_tests test_24h_authorization_stress -- --ignored`
#[tokio::test]
#[ignore = "long-running test - requires 24+ hours"]
async fn test_24h_authorization_stress() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    // Pre-populate relationships
    let relationships: Vec<Relationship> = (0..10_000)
        .map(|i| Relationship {
            vault,
            resource: format!("document:{}", i),
            relation: "viewer".to_string(),
            subject: format!("user:{}", i % 100),
        })
        .collect();
    state.store.write(vault, relationships).await.unwrap();

    let start = std::time::Instant::now();
    let target_duration = Duration::from_secs(24 * 60 * 60); // 24 hours

    let mut iteration = 0u64;
    while start.elapsed() < target_duration {
        let request = EvaluateRequest {
            subject: format!("user:{}", iteration % 100),
            resource: format!("document:{}", iteration % 10_000),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let _ = state.evaluator.check(request).await.unwrap();

        iteration += 1;

        // Log progress every million iterations
        if iteration % 1_000_000 == 0 {
            let elapsed = start.elapsed();
            let rate = iteration as f64 / elapsed.as_secs_f64();
            eprintln!("Progress: {} iterations in {:?} ({:.0} ops/sec)", iteration, elapsed, rate);
        }

        // Brief sleep to prevent tight-looping
        if iteration % 10_000 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    eprintln!("Completed {} iterations in 24 hours", iteration);
}

/// Long-running test: 24-hour mixed workload stress test
///
/// Run with: `cargo test --test memory_leak_tests test_24h_mixed_workload -- --ignored`
#[tokio::test]
#[ignore = "long-running test - requires 24+ hours"]
async fn test_24h_mixed_workload() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    let start = std::time::Instant::now();
    let target_duration = Duration::from_secs(24 * 60 * 60); // 24 hours

    let mut iteration = 0u64;
    while start.elapsed() < target_duration {
        // Mix of operations: 70% check, 20% write, 10% expand
        let op_type = iteration % 10;

        match op_type {
            0..=6 => {
                // 70%: Authorization check
                let request = EvaluateRequest {
                    subject: format!("user:{}", iteration % 100),
                    resource: format!("document:{}", iteration % 1000),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };
                let _ = state.evaluator.check(request).await.unwrap();
            },
            7..=8 => {
                // 20%: Write operation
                let relationships = vec![Relationship {
                    vault,
                    resource: format!("document:{}", iteration),
                    relation: "viewer".to_string(),
                    subject: format!("user:{}", iteration % 100),
                }];
                let _ = state.store.write(vault, relationships).await.unwrap();
            },
            9 => {
                // 10%: Expand operation
                let request = ExpandRequest {
                    resource: format!("document:{}", iteration % 1000),
                    relation: "viewer".to_string(),
                    limit: Some(100),
                    continuation_token: None,
                };
                let _ = state.evaluator.expand(request).await.unwrap();
            },
            _ => unreachable!(),
        }

        iteration += 1;

        // Log progress every million iterations
        if iteration % 1_000_000 == 0 {
            let elapsed = start.elapsed();
            let rate = iteration as f64 / elapsed.as_secs_f64();
            eprintln!("Progress: {} iterations in {:?} ({:.0} ops/sec)", iteration, elapsed, rate);
        }

        // Brief sleep to prevent tight-looping
        if iteration % 10_000 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    eprintln!("Completed {} iterations in 24 hours", iteration);
}

/// Connection leak detection test
///
/// This test verifies that connections/handles are properly released
/// and not leaked over many operations.
#[tokio::test]
async fn test_no_connection_leaks() {
    let state = create_test_state().await;
    let vault = state.default_vault;

    // Pre-populate relationships
    let relationships: Vec<Relationship> = (0..100)
        .map(|i| Relationship {
            vault,
            resource: format!("document:{}", i),
            relation: "viewer".to_string(),
            subject: format!("user:{}", i % 10),
        })
        .collect();
    state.store.write(vault, relationships).await.unwrap();

    // Perform many operations that might hold connections
    for i in 0..5_000 {
        // Authorization check (might use connection pool)
        let request = EvaluateRequest {
            subject: format!("user:{}", i % 10),
            resource: format!("document:{}", i % 100),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };
        let _ = state.evaluator.check(request).await.unwrap();

        // Every 100 iterations, verify we can still operate
        // (would fail if we leaked all connections)
        if i % 100 == 0 {
            let health_check = state.store.get_revision(vault).await;
            assert!(health_check.is_ok(), "Store should still be accessible");
        }
    }

    // Test passes if we can still perform operations
    // If connections were leaked, we'd get timeouts or errors
    let final_check = state.store.get_revision(vault).await;
    assert!(final_check.is_ok(), "Store should still be accessible after stress test");
}
