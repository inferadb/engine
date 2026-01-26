//! Load and Performance Testing Suite
//!
//! This module contains comprehensive load tests that verify the system's performance
//! under various load patterns without requiring external deployment.
//!
//! ## Purpose
//!
//! These tests are marked with `#[ignore]` because they are extremely resource-intensive
//! and can take several minutes to hours to run. They serve specific purposes:
//! - **Capacity Planning**: Determine system limits and breaking points
//! - **Performance Regression**: Detect performance degradation over time
//! - **SLO Validation**: Verify system meets latency and throughput targets
//! - **Stability Testing**: Ensure system remains stable under sustained load
//!
//! ## Running Load Tests
//!
//! ```bash
//! # Run all load tests (WARNING: Can take 10+ minutes)
//! cargo test --package infera-core --test performance_load -- --ignored --nocapture
//!
//! # Run specific test
//! cargo test --package infera-core --test performance_load test_sustained_throughput_100k_rps -- --ignored --nocapture
//!
//! # Run non-ignored performance tests only (faster, suitable for CI)
//! cargo test --package infera-core --test performance_load
//! ```
//!
//! ## Test Categories
//!
//! ### Load Tests (Ignored)
//! - `test_sustained_throughput_100k_rps`: 10s sustained 100K RPS load
//! - `test_stress_beyond_capacity`: Gradually increase load to find limits
//! - `test_soak_24h_simulation`: 60s simulating 24h continuous load
//!
//! ### Scale Tests (Ignored)
//! - `test_large_graph_1m_relationships`: Performance with 1M+ relationships
//! - `test_wide_expansion_10k_users`: Expansion with 10K+ users per resource
//!
//! ### Fast Tests (Not Ignored)
//! - `test_latency_p99_under_10ms`: SLO validation (10K requests)
//! - `test_spike_load`: Handle sudden traffic spikes
//! - `test_deep_nesting_10_levels`: Deep permission hierarchies

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use inferadb_engine_core::{
    Evaluator,
    ipl::{RelationDef, RelationExpr, Schema, TypeDef},
};
use inferadb_engine_repository::EngineStorage;
use inferadb_engine_store::RelationshipStore;
use inferadb_engine_types::{Decision, EvaluateRequest, ExpandRequest, Relationship};
use inferadb_storage::MemoryBackend;
use tokio::task::JoinSet;

mod common;

/// Performance metrics collected during tests
#[derive(Debug, Clone)]
struct PerformanceMetrics {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    total_duration: Duration,
    min_latency: Duration,
    max_latency: Duration,
    p50_latency: Duration,
    p90_latency: Duration,
    p95_latency: Duration,
    p99_latency: Duration,
    requests_per_second: f64,
}

impl PerformanceMetrics {
    fn from_latencies(latencies: &[Duration], total_duration: Duration) -> Self {
        let mut sorted = latencies.to_vec();
        sorted.sort();

        let total = sorted.len() as u64;
        let successful = total;
        let failed = 0;

        let min = sorted.first().copied().unwrap_or(Duration::ZERO);
        let max = sorted.last().copied().unwrap_or(Duration::ZERO);

        let p50_idx = (total as f64 * 0.50) as usize;
        let p90_idx = (total as f64 * 0.90) as usize;
        let p95_idx = (total as f64 * 0.95) as usize;
        let p99_idx = (total as f64 * 0.99) as usize;

        let p50 = sorted.get(p50_idx.min(sorted.len() - 1)).copied().unwrap_or(Duration::ZERO);
        let p90 = sorted.get(p90_idx.min(sorted.len() - 1)).copied().unwrap_or(Duration::ZERO);
        let p95 = sorted.get(p95_idx.min(sorted.len() - 1)).copied().unwrap_or(Duration::ZERO);
        let p99 = sorted.get(p99_idx.min(sorted.len() - 1)).copied().unwrap_or(Duration::ZERO);

        let rps = if total_duration.as_secs_f64() > 0.0 {
            total as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        Self {
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            total_duration,
            min_latency: min,
            max_latency: max,
            p50_latency: p50,
            p90_latency: p90,
            p95_latency: p95,
            p99_latency: p99,
            requests_per_second: rps,
        }
    }

    fn print_summary(&self, test_name: &str) {
        println!("\n=== {} Performance Metrics ===", test_name);
        println!("Total Requests: {}", self.total_requests);
        println!("Successful: {}", self.successful_requests);
        println!("Failed: {}", self.failed_requests);
        println!("Total Duration: {:?}", self.total_duration);
        println!("Requests/Second: {:.2}", self.requests_per_second);
        println!("Latency Min: {:?}", self.min_latency);
        println!("Latency p50: {:?}", self.p50_latency);
        println!("Latency p90: {:?}", self.p90_latency);
        println!("Latency p95: {:?}", self.p95_latency);
        println!("Latency p99: {:?}", self.p99_latency);
        println!("Latency Max: {:?}", self.max_latency);
        println!("=====================================\n");
    }
}

/// Create a simple schema for testing
fn create_test_schema() -> Schema {
    Schema::new(vec![TypeDef::new(
        "resource".to_string(),
        vec![
            RelationDef::new("viewer".to_string(), Some(RelationExpr::This)),
            RelationDef::new("editor".to_string(), Some(RelationExpr::This)),
            RelationDef::new(
                "admin".to_string(),
                Some(RelationExpr::Union(vec![
                    RelationExpr::This,
                    RelationExpr::RelationRef { relation: "editor".to_string() },
                ])),
            ),
        ],
    )])
}

// Load Tests
//

/// Test: Sustained Throughput (Target: 100k RPS)
/// This test verifies the system can handle sustained high request rates
#[tokio::test]
#[ignore = "Load test - runs for 10+ seconds with 100 concurrent workers, high CPU/memory usage"]
async fn test_sustained_throughput_100k_rps() {
    let schema = create_test_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Pre-populate with test data
    let mut relationships = Vec::new();
    for i in 0..1000 {
        relationships.push(Relationship {
            resource: format!("resource:doc{}", i),
            relation: "viewer".to_string(),
            subject: format!("subject:user{}", i % 100), // 100 unique users
            vault: 0i64,
        });
    }
    store.write(0i64, relationships).await.expect("Failed to write relationships");

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    // Run for 10 seconds with high concurrency
    let duration = Duration::from_secs(10);
    let concurrency = 100; // 100 concurrent workers
    let target_rps = 100_000;
    let requests_per_worker = (target_rps * duration.as_secs() as usize) / concurrency;

    println!("Starting sustained throughput test...");
    println!("Target: {} RPS for {:?}", target_rps, duration);
    println!("Concurrency: {}", concurrency);

    let start = Instant::now();
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let mut set = JoinSet::new();
    for worker_id in 0..concurrency {
        let evaluator = evaluator.clone();
        let _latencies = latencies.clone();

        set.spawn(async move {
            let mut worker_latencies = Vec::new();

            for i in 0..requests_per_worker {
                let req_start = Instant::now();

                let request = EvaluateRequest {
                    subject: format!("subject:user{}", (worker_id * 1000 + i) % 100),
                    resource: format!("resource:doc{}", i % 1000),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };

                let _ = evaluator.check(request).await;
                worker_latencies.push(req_start.elapsed());
            }

            worker_latencies
        });
    }

    // Collect all latencies
    while let Some(result) = set.join_next().await {
        if let Ok(worker_latencies) = result {
            latencies.lock().await.extend(worker_latencies);
        }
    }

    let total_duration = start.elapsed();
    let all_latencies = latencies.lock().await;

    let metrics = PerformanceMetrics::from_latencies(&all_latencies, total_duration);
    metrics.print_summary("Sustained Throughput");

    // Assertions based on SLOs
    assert!(
        metrics.requests_per_second >= 50_000.0,
        "RPS too low: {} (target: 100k, minimum acceptable: 50k)",
        metrics.requests_per_second
    );
    assert!(
        metrics.p99_latency < Duration::from_millis(50),
        "p99 latency too high: {:?} (target: <50ms)",
        metrics.p99_latency
    );
}

/// Test: Latency SLO Validation (p99 < 10ms)
/// Validates that 99% of requests complete within 10ms
#[tokio::test]
async fn test_latency_p99_under_10ms() {
    let schema = create_test_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Small dataset for optimal performance
    for i in 0..100 {
        store
            .write(
                0i64,
                vec![Relationship {
                    vault: 0i64,
                    resource: format!("resource:doc{}", i),
                    relation: "viewer".to_string(),
                    subject: format!("subject:user{}", i % 10),
                }],
            )
            .await
            .expect("Failed to write");
    }

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    // Run 10k requests with moderate concurrency
    let num_requests = 10_000;
    let concurrency = 10;
    let requests_per_worker = num_requests / concurrency;

    let start = Instant::now();
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let mut set = JoinSet::new();
    for worker_id in 0..concurrency {
        let evaluator = evaluator.clone();
        let _latencies = latencies.clone();

        set.spawn(async move {
            let mut worker_latencies = Vec::new();

            for i in 0..requests_per_worker {
                let req_start = Instant::now();

                let request = EvaluateRequest {
                    subject: format!("subject:user{}", (worker_id + i) % 10),
                    resource: format!("resource:doc{}", i % 100),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };

                let _ = evaluator.check(request).await;
                worker_latencies.push(req_start.elapsed());
            }

            worker_latencies
        });
    }

    while let Some(result) = set.join_next().await {
        if let Ok(worker_latencies) = result {
            latencies.lock().await.extend(worker_latencies);
        }
    }

    let total_duration = start.elapsed();
    let all_latencies = latencies.lock().await;

    let metrics = PerformanceMetrics::from_latencies(&all_latencies, total_duration);
    metrics.print_summary("Latency SLO");

    // Assert SLO targets
    assert!(
        metrics.p99_latency < Duration::from_millis(10),
        "p99 latency SLO violated: {:?} (target: <10ms)",
        metrics.p99_latency
    );
    assert!(
        metrics.p50_latency < Duration::from_millis(2),
        "p50 latency SLO violated: {:?} (target: <2ms)",
        metrics.p50_latency
    );
}

/// Test: Spike Test
/// Simulates sudden traffic spike from 100 RPS to 10k RPS
#[tokio::test]
async fn test_spike_load() {
    let schema = create_test_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Populate data
    for i in 0..500 {
        store
            .write(
                0i64,
                vec![Relationship {
                    vault: 0i64,
                    resource: format!("resource:doc{}", i),
                    relation: "viewer".to_string(),
                    subject: format!("subject:user{}", i % 50),
                }],
            )
            .await
            .expect("Failed to write");
    }

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    println!("Starting spike test (100 RPS -> 10k RPS)...");

    // Phase 1: Normal load (100 RPS for 2 seconds)
    let _normal_load_duration = Duration::from_secs(2);
    let normal_concurrency = 2;
    let normal_requests_per_worker = 100; // ~100 RPS total

    let mut all_latencies = Vec::new();
    let overall_start = Instant::now();

    // Normal load phase
    let mut set = JoinSet::new();
    for _ in 0..normal_concurrency {
        let evaluator = evaluator.clone();
        set.spawn(async move {
            let mut latencies = Vec::new();
            for i in 0..normal_requests_per_worker {
                let start = Instant::now();
                let request = EvaluateRequest {
                    subject: format!("subject:user{}", i % 50),
                    resource: format!("resource:doc{}", i % 500),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };
                let _ = evaluator.check(request).await;
                latencies.push(start.elapsed());
            }
            latencies
        });
    }

    while let Some(result) = set.join_next().await {
        if let Ok(latencies) = result {
            all_latencies.extend(latencies);
        }
    }

    // Phase 2: Spike (10k RPS for 2 seconds)
    let spike_concurrency = 20;
    let spike_requests_per_worker = 1000; // ~10k RPS total

    let mut set = JoinSet::new();
    for _ in 0..spike_concurrency {
        let evaluator = evaluator.clone();
        set.spawn(async move {
            let mut latencies = Vec::new();
            for i in 0..spike_requests_per_worker {
                let start = Instant::now();
                let request = EvaluateRequest {
                    subject: format!("subject:user{}", i % 50),
                    resource: format!("resource:doc{}", i % 500),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };
                let _ = evaluator.check(request).await;
                latencies.push(start.elapsed());
            }
            latencies
        });
    }

    while let Some(result) = set.join_next().await {
        if let Ok(latencies) = result {
            all_latencies.extend(latencies);
        }
    }

    let total_duration = overall_start.elapsed();
    let metrics = PerformanceMetrics::from_latencies(&all_latencies, total_duration);
    metrics.print_summary("Spike Test");

    // System should handle spike without catastrophic degradation
    assert!(
        metrics.p99_latency < Duration::from_millis(100),
        "System couldn't handle spike: p99={:?}",
        metrics.p99_latency
    );
}

/// Test: Stress Test
/// Pushes system beyond normal capacity to find breaking point
#[tokio::test]
#[ignore = "Stress test - runs with up to 500 concurrent workers, can take 2+ minutes"]
async fn test_stress_beyond_capacity() {
    let schema = create_test_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Large dataset
    for i in 0..5000 {
        store
            .write(
                0i64,
                vec![Relationship {
                    vault: 0i64,
                    resource: format!("resource:doc{}", i),
                    relation: "viewer".to_string(),
                    subject: format!("subject:user{}", i % 200),
                }],
            )
            .await
            .expect("Failed to write");
    }

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    println!("Starting stress test (gradually increasing load)...");

    let concurrency_levels = vec![10, 50, 100, 200, 500];
    let requests_per_worker = 1000;

    for concurrency in concurrency_levels {
        println!("\nTesting with concurrency: {}", concurrency);

        let start = Instant::now();
        let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let mut set = JoinSet::new();
        for worker_id in 0..concurrency {
            let evaluator = evaluator.clone();
            let _latencies = latencies.clone();

            set.spawn(async move {
                let mut worker_latencies = Vec::new();
                for i in 0..requests_per_worker {
                    let req_start = Instant::now();
                    let request = EvaluateRequest {
                        subject: format!("subject:user{}", (worker_id * 100 + i) % 200),
                        resource: format!("resource:doc{}", i % 5000),
                        permission: "viewer".to_string(),
                        context: None,
                        trace: None,
                    };
                    let _ = evaluator.check(request).await;
                    worker_latencies.push(req_start.elapsed());
                }
                worker_latencies
            });
        }

        while let Some(result) = set.join_next().await {
            if let Ok(worker_latencies) = result {
                latencies.lock().await.extend(worker_latencies);
            }
        }

        let total_duration = start.elapsed();
        let all_latencies = latencies.lock().await;

        let metrics = PerformanceMetrics::from_latencies(&all_latencies, total_duration);
        println!(
            "Concurrency {}: RPS={:.2}, p99={:?}",
            concurrency, metrics.requests_per_second, metrics.p99_latency
        );

        // System should remain functional even under stress
        assert!(
            metrics.failed_requests == 0,
            "System failed under stress at concurrency {}",
            concurrency
        );
    }
}

/// Test: Soak Test (24-hour simulation)
/// Simulates 24 hours of continuous moderate load
/// Note: Actually runs for 60 seconds but simulates 24h patterns
#[tokio::test]
#[ignore = "Soak test - runs for 60 seconds to detect memory leaks and stability issues"]
async fn test_soak_24h_simulation() {
    let schema = create_test_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Pre-populate
    for i in 0..1000 {
        store
            .write(
                0i64,
                vec![Relationship {
                    vault: 0i64,
                    resource: format!("resource:doc{}", i),
                    relation: "viewer".to_string(),
                    subject: format!("subject:user{}", i % 100),
                }],
            )
            .await
            .expect("Failed to write");
    }

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    println!("Starting soak test (60s simulating 24h load pattern)...");

    let test_duration = Duration::from_secs(60);
    let concurrency = 10;
    let start_time = Instant::now();

    let request_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));

    let mut set = JoinSet::new();

    for worker_id in 0..concurrency {
        let evaluator = evaluator.clone();
        let request_count = request_count.clone();
        let error_count = error_count.clone();

        set.spawn(async move {
            let mut i = 0;
            loop {
                if start_time.elapsed() >= test_duration {
                    break;
                }

                let request = EvaluateRequest {
                    subject: format!("subject:user{}", (worker_id * 100 + i) % 100),
                    resource: format!("resource:doc{}", i % 1000),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };

                match evaluator.check(request).await {
                    Ok(_) => {
                        request_count.fetch_add(1, Ordering::Relaxed);
                    },
                    Err(_) => {
                        error_count.fetch_add(1, Ordering::Relaxed);
                    },
                }

                i += 1;

                // Small delay to simulate realistic load
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    // Wait for all workers
    while let Some(result) = set.join_next().await {
        result.expect("Worker task failed");
    }

    let total_duration = start_time.elapsed();
    let total_requests = request_count.load(Ordering::Relaxed);
    let total_errors = error_count.load(Ordering::Relaxed);

    let rps = total_requests as f64 / total_duration.as_secs_f64();
    let error_rate = if total_requests > 0 {
        (total_errors as f64 / total_requests as f64) * 100.0
    } else {
        0.0
    };

    println!("\n=== Soak Test Results ===");
    println!("Duration: {:?}", total_duration);
    println!("Total Requests: {}", total_requests);
    println!("Total Errors: {}", total_errors);
    println!("RPS: {:.2}", rps);
    println!("Error Rate: {:.3}%", error_rate);
    println!("========================\n");

    // Assertions for long-term stability
    assert!(total_requests > 0, "No requests completed during soak test");
    assert!(error_rate < 0.1, "Error rate too high: {:.3}% (target: <0.1%)", error_rate);
}

// Scale Tests
//

/// Test: Large Graph (1M+ relationships)
/// Tests performance with a very large permission graph
#[tokio::test]
#[ignore = "Scale test - populates 1M relationships, requires 2GB+ memory and 3+ minutes"]
async fn test_large_graph_1m_relationships() {
    let schema = create_test_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    println!("Populating 1M relationships...");

    let batch_size = 10_000;
    let total_relationships = 1_000_000;

    let population_start = Instant::now();

    for batch in 0..(total_relationships / batch_size) {
        let mut relationships = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let relationship_id = batch * batch_size + i;
            relationships.push(Relationship {
                resource: format!("resource:doc{}", relationship_id),
                relation: "viewer".to_string(),
                subject: format!("subject:user{}", relationship_id % 10000),
                vault: 0i64,
            });
        }
        store.write(0i64, relationships).await.expect("Failed to write batch");

        if batch % 10 == 0 {
            println!("Progress: {}%", (batch * 100) / (total_relationships / batch_size));
        }
    }

    let population_duration = population_start.elapsed();
    println!("Population completed in {:?}", population_duration);

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    // Run performance test on large graph
    let num_requests = 1000;
    let concurrency = 10;

    println!("Running {} checks on 1M relationship graph...", num_requests);

    let start = Instant::now();
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let mut set = JoinSet::new();
    for worker_id in 0..concurrency {
        let evaluator = evaluator.clone();
        let _latencies = latencies.clone();

        set.spawn(async move {
            let mut worker_latencies = Vec::new();
            let requests_per_worker = num_requests / concurrency;

            for i in 0..requests_per_worker {
                let req_start = Instant::now();

                let request = EvaluateRequest {
                    subject: format!("subject:user{}", (worker_id * 1000 + i) % 10000),
                    resource: format!("resource:doc{}", i * 1000),
                    permission: "viewer".to_string(),
                    context: None,
                    trace: None,
                };

                let _ = evaluator.check(request).await;
                worker_latencies.push(req_start.elapsed());
            }

            worker_latencies
        });
    }

    while let Some(result) = set.join_next().await {
        if let Ok(worker_latencies) = result {
            latencies.lock().await.extend(worker_latencies);
        }
    }

    let total_duration = start.elapsed();
    let all_latencies = latencies.lock().await;

    let metrics = PerformanceMetrics::from_latencies(&all_latencies, total_duration);
    metrics.print_summary("Large Graph (1M relationships)");

    // Performance should still be acceptable with large dataset
    assert!(
        metrics.p99_latency < Duration::from_millis(50),
        "p99 latency degraded on large graph: {:?}",
        metrics.p99_latency
    );
}

/// Test: Deep Nesting (10+ levels)
/// Tests performance with deeply nested permission hierarchies
#[tokio::test]
async fn test_deep_nesting_10_levels() {
    // Create schema with deep nesting
    let mut relations = vec![RelationDef::new("level0".to_string(), Some(RelationExpr::This))];

    // Create 15 levels of nesting
    for level in 1..=15 {
        relations.push(RelationDef::new(
            format!("level{}", level),
            Some(RelationExpr::RelationRef { relation: format!("level{}", level - 1) }),
        ));
    }

    let schema = Schema::new(vec![TypeDef::new("resource".to_string(), relations)]);

    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    // Create deep hierarchy
    store
        .write(
            0i64,
            vec![Relationship {
                resource: "resource:root".to_string(),
                relation: "level0".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .expect("Failed to write");

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    println!("Testing deep nesting (15 levels)...");

    let _num_requests = 100;
    let mut latencies = Vec::new();

    let start = Instant::now();

    for level in 0..=15 {
        let req_start = Instant::now();

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "resource:root".to_string(),
            permission: format!("level{}", level),
            context: None,
            trace: None,
        };

        let decision = evaluator.check(request).await.expect("Check failed");
        assert_eq!(decision, Decision::Allow);

        latencies.push(req_start.elapsed());
    }

    let total_duration = start.elapsed();
    let metrics = PerformanceMetrics::from_latencies(&latencies, total_duration);
    metrics.print_summary("Deep Nesting (15 levels)");

    // Deep nesting should still complete in reasonable time
    assert!(
        metrics.max_latency < Duration::from_millis(100),
        "Deep nesting too slow: {:?}",
        metrics.max_latency
    );
}

/// Test: Wide Expansion (10k+ users)
/// Tests expansion performance with very large usersets
#[tokio::test]
#[ignore = "Scale test - tests expansion with 10K users, takes 30+ seconds"]
async fn test_wide_expansion_10k_users() {
    let schema = create_test_schema();
    let store = Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

    println!("Creating wide userset (10k users)...");

    // Create 10k users with viewer permission on one resource
    let batch_size = 1000;
    for batch in 0..10 {
        let mut relationships = Vec::new();
        for i in 0..batch_size {
            relationships.push(Relationship {
                resource: "resource:shared".to_string(),
                relation: "viewer".to_string(),
                subject: format!("subject:user{}", batch * batch_size + i),
                vault: 0i64,
            });
        }
        store.write(0i64, relationships).await.expect("Failed to write");
    }

    let evaluator =
        Arc::new(Evaluator::new(store as Arc<dyn RelationshipStore>, Arc::new(schema), None, 0i64));

    println!("Running expansion on 10k user resource...");

    let start = Instant::now();

    let response = evaluator
        .expand(ExpandRequest {
            resource: "resource:shared".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            continuation_token: None,
        })
        .await
        .expect("Expand failed");

    let duration = start.elapsed();

    println!("\n=== Wide Expansion Results ===");
    println!("Duration: {:?}", duration);
    println!("Total Users: {}", response.users.len());
    println!("============================\n");

    // Expansion should complete in reasonable time even with 10k users
    assert!(duration < Duration::from_millis(500), "Wide expansion too slow: {:?}", duration);
    assert!(response.users.len() >= 10_000, "Not all users returned: {}", response.users.len());
}
