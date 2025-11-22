//! API Throughput Benchmarks
//!
//! These benchmarks measure the throughput and performance characteristics
//! of the InferaDB API layer, including:
//! - Authorization check operations (target: 10,000 RPS)
//! - Relationship write operations
//! - Expand operations
//! - Mixed workloads
//!
//! Run with: `cargo bench --package infera-api`

use std::{hint::black_box, sync::Arc};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use infera_api::AppState;
use infera_config::Config;
use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use infera_store::MemoryBackend;
use infera_types::{EvaluateRequest, ExpandRequest, ListRelationshipsRequest, Relationship};

/// Create a test schema with realistic complexity
fn create_test_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new(
                    "editor".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "owner".to_string() },
                    ])),
                ),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                    ])),
                ),
            ],
        ),
        TypeDef::new(
            "folder".to_string(),
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
        ),
    ]))
}

/// Create test AppState with pre-populated data
async fn create_test_state_with_data(num_relationships: usize) -> AppState {
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    let schema = create_test_schema();
    let vault: i64 = 1;
    let organization: i64 = 1;

    // Pre-populate with relationships
    let relationships: Vec<Relationship> = (0..num_relationships)
        .map(|i| Relationship {
            vault,
            resource: format!("document:{}", i),
            relation: "viewer".to_string(),
            subject: format!("user:{}", i % 100), // 100 unique users
        })
        .collect();

    let _ = store.write(vault, relationships).await;

    let mut config = Config::default();
    config.cache.enabled = true;
    config.cache.max_capacity = 10000;
    config.auth.enabled = false;

    AppState::new(store, schema, None, Arc::new(config), None, vault, organization, None)
}

/// Benchmark: Authorization check (check if user has permission)
/// Target: 10,000 RPS
fn bench_authorization_check(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Pre-create state with 1000 relationships
    let state = runtime.block_on(create_test_state_with_data(1000));
    let vault = state.default_vault;

    let mut group = c.benchmark_group("authorization_check");

    // Vary the complexity
    for num_docs in [1, 10, 100, 1000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_docs", num_docs)),
            &num_docs,
            |b, _| {
                b.to_async(&runtime).iter(|| async {
                    let request = EvaluateRequest {
                        resource: format!("document:{}", black_box(50)),
                        permission: "viewer".to_string(),
                        subject: "user:alice".to_string(),
                        context: None,
                        trace: None,
                    };

                    black_box(state.evaluation_service.evaluate(vault, request).await.unwrap())
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Relationship writes
fn bench_relationship_write(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let state = runtime.block_on(create_test_state_with_data(100));
    let vault = state.default_vault;

    let mut group = c.benchmark_group("relationship_write");

    // Vary batch size
    for batch_size in [1, 10, 50, 100] {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_relationships", batch_size)),
            &batch_size,
            |b, &size| {
                b.to_async(&runtime).iter(|| async {
                    let relationships: Vec<Relationship> = (0..size)
                        .map(|i| Relationship {
                            vault,
                            resource: format!("document:bench_{}", i),
                            relation: "viewer".to_string(),
                            subject: "user:bench".to_string(),
                        })
                        .collect();

                    black_box(state.store.write(vault, relationships).await.unwrap())
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Expand operations (find all users with permission)
fn bench_expand_operation(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let state = runtime.block_on(create_test_state_with_data(500));
    let vault = state.default_vault;

    let mut group = c.benchmark_group("expand_operation");
    group.throughput(Throughput::Elements(1));

    group.bench_function("expand_viewer", |b| {
        b.to_async(&runtime).iter(|| async {
            let request = ExpandRequest {
                resource: "document:50".to_string(),
                relation: "viewer".to_string(),
                limit: None,
                continuation_token: None,
            };

            black_box(state.expansion_service.expand(vault, request).await.unwrap())
        });
    });

    group.finish();
}

/// Benchmark: List relationships
fn bench_list_relationships(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let state = runtime.block_on(create_test_state_with_data(1000));
    let vault = state.default_vault;

    let mut group = c.benchmark_group("list_relationships");

    for limit in [10, 50, 100, 500] {
        group.throughput(Throughput::Elements(limit as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("limit_{}", limit)),
            &limit,
            |b, &lim| {
                b.to_async(&runtime).iter(|| async {
                    let request = ListRelationshipsRequest {
                        resource: None,
                        relation: Some("viewer".to_string()),
                        subject: None,
                        limit: Some(lim),
                        cursor: None,
                    };

                    black_box(
                        state
                            .relationship_service
                            .list_relationships(vault, request)
                            .await
                            .unwrap(),
                    )
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Mixed workload (realistic usage pattern)
/// 70% reads (check), 20% writes, 10% expand
fn bench_mixed_workload(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let state = runtime.block_on(create_test_state_with_data(500));
    let vault = state.default_vault;

    let mut group = c.benchmark_group("mixed_workload");
    group.throughput(Throughput::Elements(10)); // 10 operations per iteration

    group.bench_function("realistic_mix", |b| {
        b.to_async(&runtime).iter(|| async {
            // 7 check operations (70%)
            for i in 0..7 {
                let request = EvaluateRequest {
                    resource: format!("document:{}", black_box(i * 10)),
                    permission: "viewer".to_string(),
                    subject: format!("user:{}", black_box(i)),
                    context: None,
                    trace: None,
                };
                let _ = state.evaluation_service.evaluate(vault, request).await.unwrap();
            }

            // 2 write operations (20%)
            for i in 0..2 {
                let relationships = vec![Relationship {
                    vault,
                    resource: format!("document:mixed_{}", i),
                    relation: "viewer".to_string(),
                    subject: "user:mixed".to_string(),
                }];
                let _ = state.store.write(vault, relationships).await.unwrap();
            }

            // 1 expand operation (10%)
            let expand_request = ExpandRequest {
                resource: "document:50".to_string(),
                relation: "viewer".to_string(),
                limit: None,
                continuation_token: None,
            };
            black_box(state.expansion_service.expand(vault, expand_request).await.unwrap())
        });
    });

    group.finish();
}

/// Benchmark: Cache hit vs cache miss performance
fn bench_cache_effectiveness(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let state = runtime.block_on(create_test_state_with_data(100));
    let vault = state.default_vault;

    let mut group = c.benchmark_group("cache_effectiveness");

    // Warm up cache
    let request = EvaluateRequest {
        resource: "document:50".to_string(),
        permission: "viewer".to_string(),
        subject: "user:alice".to_string(),
        context: None,
        trace: None,
    };
    runtime.block_on(state.evaluation_service.evaluate(vault, request.clone())).unwrap();

    group.bench_function("cache_hit", |b| {
        b.to_async(&runtime).iter(|| async {
            let request = EvaluateRequest {
                resource: "document:50".to_string(),
                permission: "viewer".to_string(),
                subject: "user:alice".to_string(),
                context: None,
                trace: None,
            };
            black_box(state.evaluation_service.evaluate(vault, request).await.unwrap())
        });
    });

    group.bench_function("cache_miss", |b| {
        b.to_async(&runtime).iter(|| async {
            // Different resource each time to force cache miss
            let request = EvaluateRequest {
                resource: format!("document:unique_{}", black_box(rand::random::<u32>())),
                permission: "viewer".to_string(),
                subject: "user:alice".to_string(),
                context: None,
                trace: None,
            };
            black_box(state.evaluation_service.evaluate(vault, request).await.unwrap())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_authorization_check,
    bench_relationship_write,
    bench_expand_operation,
    bench_list_relationships,
    bench_mixed_workload,
    bench_cache_effectiveness,
);
criterion_main!(benches);
