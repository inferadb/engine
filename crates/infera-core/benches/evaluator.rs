use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use infera_core::{Evaluator, CheckRequest, ExpandRequest};
use infera_core::ipl::{Schema, TypeDef, RelationDef, RelationExpr};
use infera_store::{MemoryBackend, Tuple, TupleStore};

fn create_complex_schema() -> Schema {
    Schema::new(vec![
        TypeDef::new("folder".to_string(), vec![
            RelationDef::new("owner".to_string(), None),
            RelationDef::new("viewer".to_string(), Some(RelationExpr::Union(vec![
                RelationExpr::This,
                RelationExpr::RelationRef { relation: "owner".to_string() },
            ]))),
        ]),
        TypeDef::new("doc".to_string(), vec![
            RelationDef::new("parent".to_string(), None),
            RelationDef::new("owner".to_string(), None),
            RelationDef::new("editor".to_string(), Some(RelationExpr::Union(vec![
                RelationExpr::This,
                RelationExpr::RelationRef { relation: "owner".to_string() },
            ]))),
            RelationDef::new("viewer".to_string(), Some(RelationExpr::Union(vec![
                RelationExpr::This,
                RelationExpr::RelationRef { relation: "editor".to_string() },
                RelationExpr::TupleToUserset {
                    tupleset: "parent".to_string(),
                    computed: "viewer".to_string(),
                },
            ]))),
        ]),
    ])
}

async fn setup_evaluator_with_data(num_tuples: usize) -> Evaluator {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Create test data
    let mut tuples = Vec::new();
    for i in 0..num_tuples {
        tuples.push(Tuple {
            object: format!("doc:{}", i),
            relation: "owner".to_string(),
            user: format!("user:{}", i),
        });
    }
    store.write(tuples).await.unwrap();

    Evaluator::new(store, schema, None)
}

fn bench_direct_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("direct_check_allow", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(100));

        b.to_async(&rt).iter(|| async {
            let request = CheckRequest {
                subject: "user:0".to_string(),
                resource: "doc:0".to_string(),
                permission: "owner".to_string(),
                context: None,
            };

            black_box(evaluator.check(request).await.unwrap())
        });
    });

    c.bench_function("direct_check_deny", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(100));

        b.to_async(&rt).iter(|| async {
            let request = CheckRequest {
                subject: "user:99".to_string(),
                resource: "doc:0".to_string(),
                permission: "owner".to_string(),
                context: None,
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
            let request = CheckRequest {
                subject: "user:0".to_string(),
                resource: "doc:0".to_string(),
                permission: "editor".to_string(), // editor = this | owner
                context: None,
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

            // Create nested hierarchy
            let tuples = vec![
                Tuple {
                    object: "folder:root".to_string(),
                    relation: "owner".to_string(),
                    user: "user:admin".to_string(),
                },
                Tuple {
                    object: "doc:readme".to_string(),
                    relation: "parent".to_string(),
                    user: "folder:root".to_string(),
                },
            ];
            store.write(tuples).await.unwrap();

            Evaluator::new(store, schema, None)
        });

        b.to_async(&rt).iter(|| async {
            let request = CheckRequest {
                subject: "user:admin".to_string(),
                resource: "doc:readme".to_string(),
                permission: "viewer".to_string(), // Should traverse parent->viewer
                context: None,
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
            };

            black_box(evaluator.expand(request).await.unwrap())
        });
    });
}

fn bench_large_scale(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("check_with_1000_tuples", |b| {
        let evaluator = rt.block_on(setup_evaluator_with_data(1000));

        b.to_async(&rt).iter(|| async {
            let request = CheckRequest {
                subject: "user:500".to_string(),
                resource: "doc:500".to_string(),
                permission: "owner".to_string(),
                context: None,
            };

            black_box(evaluator.check(request).await.unwrap())
        });
    });
}

criterion_group!(
    benches,
    bench_direct_check,
    bench_union_check,
    bench_complex_check,
    bench_expand,
    bench_large_scale
);
criterion_main!(benches);
