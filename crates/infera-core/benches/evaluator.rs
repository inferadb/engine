use std::{hint::black_box, sync::Arc};

use criterion::{Criterion, criterion_group, criterion_main};
use infera_core::{
    Evaluator,
    ipl::{RelationDef, RelationExpr, Schema, TypeDef},
};
use infera_store::{MemoryBackend, RelationshipStore};
use infera_types::{EvaluateRequest, ExpandRequest, Relationship};
use uuid::Uuid;

fn create_complex_schema() -> Schema {
    Schema::new(vec![
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
        TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("parent".to_string(), None),
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
                        RelationExpr::RelatedObjectUserset {
                            relationship: "parent".to_string(),
                            computed: "viewer".to_string(),
                        },
                    ])),
                ),
            ],
        ),
    ])
}

async fn setup_evaluator_with_data(num_relationships: usize) -> Evaluator {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());
    let vault = Uuid::new_v4();

    // Create test data
    let mut relationships = Vec::new();
    for i in 0..num_relationships {
        relationships.push(Relationship {
            vault,
            resource: format!("doc:{}", i),
            relation: "owner".to_string(),
            subject: format!("subject:{}", i),
        });
    }
    store.write(vault, relationships).await.unwrap();

    Evaluator::new(store as Arc<dyn RelationshipStore>, schema, None, vault)
}

fn bench_direct_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("direct_check_allow", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(100));

        b.to_async(&rt).iter(|| async {
            let request = EvaluateRequest {
                subject: "subject:0".to_string(),
                resource: "doc:0".to_string(),
                permission: "owner".to_string(),
                context: None,
                trace: None,
            };

            black_box(evaluator.check(request).await.unwrap())
        });
    });

    c.bench_function("direct_check_deny", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(100));

        b.to_async(&rt).iter(|| async {
            let request = EvaluateRequest {
                subject: "subject:99".to_string(),
                resource: "doc:0".to_string(),
                permission: "owner".to_string(),
                context: None,
                trace: None,
            };

            black_box(evaluator.check(request).await.unwrap())
        });
    });
}

fn bench_union_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("union_check_allow", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(100));

        b.to_async(&rt).iter(|| async {
            let request = EvaluateRequest {
                subject: "subject:0".to_string(),
                resource: "doc:0".to_string(),
                permission: "editor".to_string(), // editor = this | owner
                context: None,
                trace: None,
            };

            black_box(evaluator.check(request).await.unwrap())
        });
    });
}

fn bench_complex_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("complex_check_with_trace", |b| {
        let evaluator = rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());
            let schema = Arc::new(create_complex_schema());
            let vault = Uuid::new_v4();

            // Create nested hierarchy
            let relationships = vec![
                Relationship {
                    vault,
                    resource: "folder:root".to_string(),
                    relation: "owner".to_string(),
                    subject: "subject:admin".to_string(),
                },
                Relationship {
                    vault,
                    resource: "doc:readme".to_string(),
                    relation: "parent".to_string(),
                    subject: "folder:root".to_string(),
                },
            ];
            store.write(vault, relationships).await.unwrap();

            Evaluator::new(store as Arc<dyn RelationshipStore>, schema, None, vault)
        });

        b.to_async(&rt).iter(|| async {
            let request = EvaluateRequest {
                subject: "subject:admin".to_string(),
                resource: "doc:readme".to_string(),
                permission: "viewer".to_string(), // Should traverse parent->viewer
                context: None,
                trace: None,
            };

            black_box(evaluator.check_with_trace(request).await.unwrap())
        });
    });
}

fn bench_expand(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("expand_simple", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(10));

        b.to_async(&rt).iter(|| async {
            let request = ExpandRequest {
                resource: "doc:0".to_string(),
                relation: "owner".to_string(),
                limit: None,
                continuation_token: None,
            };

            black_box(evaluator.expand(request).await.unwrap())
        });
    });

    c.bench_function("expand_complex", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(10));

        b.to_async(&rt).iter(|| async {
            let request = ExpandRequest {
                resource: "doc:0".to_string(),
                relation: "viewer".to_string(), // Complex union expression
                limit: None,
                continuation_token: None,
            };

            black_box(evaluator.expand(request).await.unwrap())
        });
    });
}

fn bench_parallel_expand(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Benchmark parallel expansion with multiple branches
    c.bench_function("expand_parallel_4_branches", |b| {
        let evaluator = rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());
            let vault = Uuid::new_v4();

            // Create schema with 4 independent branches
            let schema = Arc::new(Schema::new(vec![TypeDef::new(
                "doc".to_string(),
                vec![
                    RelationDef::new("admin".to_string(), None),
                    RelationDef::new("editor".to_string(), None),
                    RelationDef::new("viewer".to_string(), None),
                    RelationDef::new("contributor".to_string(), None),
                    RelationDef::new(
                        "any_access".to_string(),
                        Some(RelationExpr::Union(vec![
                            RelationExpr::RelationRef { relation: "admin".to_string() },
                            RelationExpr::RelationRef { relation: "editor".to_string() },
                            RelationExpr::RelationRef { relation: "viewer".to_string() },
                            RelationExpr::RelationRef { relation: "contributor".to_string() },
                        ])),
                    ),
                ],
            )]));

            // Create 100 users distributed across the 4 branches
            let mut relationships = Vec::new();
            for i in 0..100 {
                let relation = match i % 4 {
                    0 => "admin",
                    1 => "editor",
                    2 => "viewer",
                    _ => "contributor",
                };
                relationships.push(Relationship {
                    vault,
                    resource: "doc:readme".to_string(),
                    relation: relation.to_string(),
                    subject: format!("subject:{}", i),
                });
            }
            store.write(vault, relationships).await.unwrap();

            Evaluator::new(store as Arc<dyn RelationshipStore>, schema, None, vault)
        });

        b.to_async(&rt).iter(|| async {
            let request = ExpandRequest {
                resource: "doc:readme".to_string(),
                relation: "any_access".to_string(),
                limit: None,
                continuation_token: None,
            };

            black_box(evaluator.expand(request).await.unwrap())
        });
    });

    // Benchmark parallel expansion with nested intersections
    c.bench_function("expand_parallel_intersection", |b| {
        let evaluator = rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());
            let vault = Uuid::new_v4();

            let schema = Arc::new(Schema::new(vec![TypeDef::new(
                "doc".to_string(),
                vec![
                    RelationDef::new("group_a".to_string(), None),
                    RelationDef::new("group_b".to_string(), None),
                    RelationDef::new("group_c".to_string(), None),
                    RelationDef::new(
                        "all_groups".to_string(),
                        Some(RelationExpr::Intersection(vec![
                            RelationExpr::RelationRef { relation: "group_a".to_string() },
                            RelationExpr::RelationRef { relation: "group_b".to_string() },
                            RelationExpr::RelationRef { relation: "group_c".to_string() },
                        ])),
                    ),
                ],
            )]));

            // Create overlapping user sets
            let mut relationships = Vec::new();
            for i in 0..50 {
                relationships.push(Relationship {
                    vault,
                    resource: "doc:readme".to_string(),
                    relation: "group_a".to_string(),
                    subject: format!("subject:{}", i),
                });
                if i < 30 {
                    relationships.push(Relationship {
                        vault,
                        resource: "doc:readme".to_string(),
                        relation: "group_b".to_string(),
                        subject: format!("subject:{}", i),
                    });
                }
                if i < 20 {
                    relationships.push(Relationship {
                        vault,
                        resource: "doc:readme".to_string(),
                        relation: "group_c".to_string(),
                        subject: format!("subject:{}", i),
                    });
                }
            }
            store.write(vault, relationships).await.unwrap();

            Evaluator::new(store as Arc<dyn RelationshipStore>, schema, None, vault)
        });

        b.to_async(&rt).iter(|| async {
            let request = ExpandRequest {
                resource: "doc:readme".to_string(),
                relation: "all_groups".to_string(),
                limit: None,
                continuation_token: None,
            };

            black_box(evaluator.expand(request).await.unwrap())
        });
    });
}

fn bench_large_scale(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("check_with_1000_relationships", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(1000));

        b.to_async(&rt).iter(|| async {
            let request = EvaluateRequest {
                subject: "subject:500".to_string(),
                resource: "doc:500".to_string(),
                permission: "owner".to_string(),
                context: None,
                trace: None,
            };

            black_box(evaluator.check(request).await.unwrap())
        });
    });
}

fn bench_expand_cache(c: &mut Criterion) {
    use std::time::Duration;

    use infera_cache::AuthCache;
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Benchmark expand with cache enabled (repeated queries)
    c.bench_function("expand_with_cache_hit", |b| {
        let evaluator = rt.block_on(async {
            let store = Arc::new(MemoryBackend::new());
            let vault = Uuid::new_v4();

            let schema = Arc::new(Schema::new(vec![TypeDef::new(
                "doc".to_string(),
                vec![
                    RelationDef::new("reader".to_string(), None),
                    RelationDef::new("editor".to_string(), None),
                    RelationDef::new(
                        "viewer".to_string(),
                        Some(RelationExpr::Union(vec![
                            RelationExpr::RelationRef { relation: "reader".to_string() },
                            RelationExpr::RelationRef { relation: "editor".to_string() },
                        ])),
                    ),
                ],
            )]));

            // Write 50 users
            let mut relationships = Vec::new();
            for i in 0..50 {
                relationships.push(Relationship {
                    vault,
                    resource: "doc:readme".to_string(),
                    relation: "reader".to_string(),
                    subject: format!("subject:{}", i),
                });
            }
            store.write(vault, relationships).await.unwrap();

            let cache = Arc::new(AuthCache::new(10_000, Duration::from_secs(300)));
            Evaluator::new_with_cache(
                store as Arc<dyn RelationshipStore>,
                schema,
                None,
                Some(cache),
                vault,
            )
        });

        // First request will populate cache
        let _ = rt.block_on(async {
            let request = ExpandRequest {
                resource: "doc:readme".to_string(),
                relation: "viewer".to_string(),
                limit: None,
                continuation_token: None,
            };
            evaluator.expand(request).await.unwrap()
        });

        // Now benchmark cached requests
        b.to_async(&rt).iter(|| async {
            let request = ExpandRequest {
                resource: "doc:readme".to_string(),
                relation: "viewer".to_string(),
                limit: None,
                continuation_token: None,
            };

            black_box(evaluator.expand(request).await.unwrap())
        });
    });
}

criterion_group!(
    benches,
    bench_direct_check,
    bench_union_check,
    bench_complex_check,
    bench_expand,
    bench_parallel_expand,
    bench_expand_cache,
    bench_large_scale
);
criterion_main!(benches);
