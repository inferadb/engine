use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use inferadb_core::ipl::parse_schema;

fn simple_schema() -> &'static str {
    r#"
    type document {
        relation owner
        relation viewer: this | owner
    }
    "#
}

fn complex_schema() -> &'static str {
    r#"
    type organization {
        relation member
        relation admin: this | member
    }

    type folder {
        relation parent
        relation owner
        relation viewer: this | owner | viewer from parent
    }

    type document {
        relation parent
        relation owner
        relation editor: this | owner
        relation viewer: this | editor | viewer from parent | viewer from owner
        relation commenter: viewer - editor
    }
    "#
}

fn very_complex_schema() -> &'static str {
    r#"
    type organization {
        relation member
        relation admin
        relation viewer: this | member
    }

    type team {
        relation organization
        relation member
        relation admin: member from organization | this
        relation viewer: this | member | admin
    }

    type folder {
        relation parent
        relation owner
        relation team
        relation editor: this | owner | editor from parent | member from team
        relation viewer: this | editor | viewer from parent | viewer from team
    }

    type document {
        relation parent
        relation owner
        relation editor: this | owner | editor from parent
        relation viewer: this | editor | viewer from parent
        relation commenter: viewer - editor
        relation restricted: module("business_hours")
    }

    type group {
        relation member
        relation admin: this | member
        relation viewer: member | admin
    }
    "#
}

fn benchmark_simple_parse(c: &mut Criterion) {
    c.bench_function("parse simple schema", |b| {
        b.iter(|| parse_schema(black_box(simple_schema())))
    });
}

fn benchmark_complex_parse(c: &mut Criterion) {
    c.bench_function("parse complex schema", |b| {
        b.iter(|| parse_schema(black_box(complex_schema())))
    });
}

fn benchmark_very_complex_parse(c: &mut Criterion) {
    c.bench_function("parse very complex schema", |b| {
        b.iter(|| parse_schema(black_box(very_complex_schema())))
    });
}

criterion_group!(
    benches,
    benchmark_simple_parse,
    benchmark_complex_parse,
    benchmark_very_complex_parse
);
criterion_main!(benches);
