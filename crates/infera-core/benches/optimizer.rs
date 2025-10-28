//! Benchmarks for query optimizer

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use infera_core::ipl::{RelationDef, RelationExpr};
use infera_core::optimizer::QueryPlanner;

fn bench_plan_simple(c: &mut Criterion) {
    let relation = RelationDef {
        name: "viewer".to_string(),
        expr: Some(RelationExpr::This),
    };

    c.bench_function("plan_simple_relation", |b| {
        b.iter(|| {
            QueryPlanner::plan_relation(black_box(&relation), black_box("viewer"))
        })
    });
}

fn bench_plan_union(c: &mut Criterion) {
    let relation = RelationDef {
        name: "viewer".to_string(),
        expr: Some(RelationExpr::Union(vec![
            RelationExpr::This,
            RelationExpr::RelationRef {
                relation: "owner".to_string(),
            },
            RelationExpr::TupleToUserset {
                tupleset: "parent".to_string(),
                computed: "viewer".to_string(),
            },
        ])),
    };

    c.bench_function("plan_union_relation", |b| {
        b.iter(|| {
            QueryPlanner::plan_relation(black_box(&relation), black_box("viewer"))
        })
    });
}

fn bench_plan_complex(c: &mut Criterion) {
    let relation = RelationDef {
        name: "viewer".to_string(),
        expr: Some(RelationExpr::Union(vec![
            RelationExpr::This,
            RelationExpr::Intersection(vec![
                RelationExpr::RelationRef {
                    relation: "editor".to_string(),
                },
                RelationExpr::RelationRef {
                    relation: "owner".to_string(),
                },
            ]),
            RelationExpr::Exclusion {
                base: Box::new(RelationExpr::TupleToUserset {
                    tupleset: "parent".to_string(),
                    computed: "viewer".to_string(),
                }),
                subtract: Box::new(RelationExpr::RelationRef {
                    relation: "blocked".to_string(),
                }),
            },
        ])),
    };

    c.bench_function("plan_complex_relation", |b| {
        b.iter(|| {
            QueryPlanner::plan_relation(black_box(&relation), black_box("viewer"))
        })
    });
}

fn bench_analyze_plan(c: &mut Criterion) {
    let relation = RelationDef {
        name: "viewer".to_string(),
        expr: Some(RelationExpr::Union(vec![
            RelationExpr::TupleToUserset {
                tupleset: "parent".to_string(),
                computed: "viewer".to_string(),
            },
            RelationExpr::TupleToUserset {
                tupleset: "parent".to_string(),
                computed: "editor".to_string(),
            },
            RelationExpr::TupleToUserset {
                tupleset: "parent".to_string(),
                computed: "owner".to_string(),
            },
        ])),
    };

    let plan = QueryPlanner::plan_relation(&relation, "viewer");

    c.bench_function("analyze_plan", |b| {
        b.iter(|| {
            QueryPlanner::analyze_plan(black_box(&plan))
        })
    });
}

fn bench_identify_prefetch(c: &mut Criterion) {
    let relation = RelationDef {
        name: "viewer".to_string(),
        expr: Some(RelationExpr::Union(vec![
            RelationExpr::This,
            RelationExpr::TupleToUserset {
                tupleset: "parent".to_string(),
                computed: "viewer".to_string(),
            },
        ])),
    };

    let plan = QueryPlanner::plan_relation(&relation, "viewer");

    c.bench_function("identify_prefetch_candidates", |b| {
        b.iter(|| {
            QueryPlanner::identify_prefetch_candidates(
                black_box("document:readme"),
                black_box(&plan),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_plan_simple,
    bench_plan_union,
    bench_plan_complex,
    bench_analyze_plan,
    bench_identify_prefetch
);
criterion_main!(benches);
