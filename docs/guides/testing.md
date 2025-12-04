# Testing Guide

InferaDB has comprehensive test coverage including unit tests, integration tests, property-based tests, benchmarks, and security tests. This guide covers how to run and write tests.

## Quick Start

```bash
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run a specific test
cargo test test_check_allow

# Run tests in a specific package
cargo test --package inferadb-core

# Run tests matching a pattern
cargo test check_
```

## Test Organization

InferaDB's test suite is organized into several categories:

```plaintext
server/
├── crates/
│   ├── inferadb-core/
│   │   ├── src/
│   │   │   ├── evaluator.rs
│   │   │   │   └── #[cfg(test)] mod tests { ... }  # Unit tests
│   │   ├── tests/
│   │   │   ├── document_management.rs               # Integration tests
│   │   │   ├── organization_hierarchy.rs
│   │   │   ├── role_based_access.rs
│   │   │   └── ipl_parser_fuzz.rs                  # Fuzz tests
│   │   └── benches/
│   │       ├── evaluator.rs                         # Benchmarks
│   │       └── ipl_parser.rs
│   ├── inferadb-store/
│   │   ├── src/
│   │   │   ├── memory.rs
│   │   │   │   └── #[cfg(test)] mod tests { ... }
│   │   │   │   └── #[cfg(test)] mod proptests { ... }  # Property tests
│   │   └── benches/
│   │       └── memory_backend.rs
│   └── inferadb-wasm/
│       └── tests/
│           └── sandbox_security.rs                  # Security tests
```

## Test Categories

### Unit Tests

Unit tests are co-located with the code they test.

**Location**: `src/**/*.rs` (in `#[cfg(test)] mod tests`)

**Run**:

```bash
cargo test --lib
```

**Example**:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_direct_tuple() {
        let store = Arc::new(MemoryBackend::new());
        let schema = create_test_schema();
        let evaluator = Evaluator::new(store.clone(), schema, None);

        // Write tuple
        store.write(vec![Tuple {
            object: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            user: "user:alice".to_string(),
        }]).await.unwrap();

        // Check permission
        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
        };

        let decision = evaluator.check(request).await.unwrap();
        assert_eq!(decision, Decision::Allow);
    }
}
```

---

### Integration Tests

Integration tests verify end-to-end scenarios.

**Location**: `crates/*/tests/*.rs`

**Run**:

```bash
cargo test --test '*'
```

**Example Tests**:

1. **Document Management** ([`tests/document_management.rs`](../crates/inferadb-core/tests/document_management.rs))
   - Direct document permissions
   - Editor and viewer permissions
   - Hierarchical folder permissions
   - Permission revocation

2. **Organization Hierarchy** ([`tests/organization_hierarchy.rs`](../crates/inferadb-core/tests/organization_hierarchy.rs))
   - Organization admin permissions
   - Team member permissions
   - Hierarchical org-to-team-to-project permissions
   - Multi-level hierarchy

3. **Role-Based Access Control** ([`tests/role_based_access.rs`](../crates/inferadb-core/tests/role_based_access.rs))
   - Basic role assignment
   - Role hierarchy
   - Multiple roles per user
   - RBAC with multiple users

**Example**:

```rust
#[tokio::test]
async fn test_document_hierarchy() {
    let fixture = TestFixture::new().await;

    // Create schema
    fixture.apply_schema(/* IPL schema */);

    // Set up hierarchy
    fixture.write_tuple("doc:readme", "parent", "folder:shared").await;
    fixture.write_tuple("folder:shared", "viewer", "user:alice").await;

    // Test: alice has viewer on doc through folder
    fixture.assert_allowed("user:alice", "doc:readme", "viewer").await;
}
```

---

### Property-Based Tests

Property-based tests use randomized inputs to find edge cases.

**Location**: `src/**/*.rs` (in `#[cfg(test)] mod proptests`)

**Run**:

```bash
cargo test prop_
```

**Example**:

```rust
use proptest::prelude::*;

fn tuple_strategy() -> impl Strategy<Value = Tuple> {
    (
        "[a-z]+:[a-z0-9]+",  // object
        "[a-z_]+",           // relation
        "user:[a-z]+",       // user
    )
        .prop_map(|(object, relation, user)| Tuple {
            object,
            relation,
            user,
        })
}

proptest! {
    #[test]
    fn prop_write_then_read_succeeds(
        tuples in prop::collection::vec(tuple_strategy(), 1..50)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = MemoryBackend::new();

            // Write tuples
            let rev = store.write(tuples.clone()).await.unwrap();

            // Read back and verify
            for tuple in &tuples {
                let key = TupleKey {
                    object: tuple.object.clone(),
                    relation: tuple.relation.clone(),
                    user: None,
                };
                let results = store.read(&key, rev).await.unwrap();

                // Tuple should be found
                let found = results.iter().any(|t| {
                    t.object == tuple.object &&
                    t.relation == tuple.relation &&
                    t.user == tuple.user
                });
                prop_assert!(found);
            }
            Ok(())
        })?;
    }
}
```

**Coverage**: 8 property tests in memory backend covering:

- Write-then-read roundtrip
- Monotonic revision increases
- Duplicate prevention
- Deletion
- MVCC isolation
- User filtering
- Batch atomicity
- GC correctness

---

### Fuzz Tests

Fuzz tests use random inputs to find parser bugs.

**Location**: `crates/inferadb-core/tests/ipl_parser_fuzz.rs`

**Run**:

```bash
cargo test fuzz_
```

**Example**:

```rust
proptest! {
    #[test]
    fn fuzz_type_name(name in "[a-z][a-z0-9_]{0,50}") {
        let input = format!("type {} {{}}", name);
        let result = parse_ipl(&input);
        // Should either parse successfully or fail gracefully
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn fuzz_random_input(input in "\\PC{0,100}") {
        // Random Unicode input should not crash parser
        let result = parse_ipl(&input);
        // Should not panic
    }
}
```

**Coverage**: 22 fuzz tests covering:

- Type names
- Relation names
- Expressions
- Random inputs
- Malformed syntax
- Edge cases

---

### Security Tests

Security tests verify sandbox isolation and resource limits.

**Location**: `crates/inferadb-wasm/tests/sandbox_security.rs`

**Run**:

```bash
cargo test --package inferadb-wasm --test sandbox_security
```

**Example Tests**:

1. **Memory Limit Enforcement**
   - Modules cannot exceed memory limits
   - Out-of-bounds access detected

2. **Fuel Limit Enforcement**
   - Infinite loops are terminated
   - CPU limits prevent DoS

3. **Filesystem/Network Isolation**
   - WASI disabled (no filesystem access)
   - No network access possible

4. **Module Isolation**
   - Modules from different tenants isolated
   - No shared state between modules

5. **Malicious Code Prevention**
   - Invalid bytecode rejected
   - Stack overflow prevented
   - Memory bounds enforced

**Example**:

```rust
#[test]
fn test_fuel_limit_enforcement() {
    let host = WasmHost::new().unwrap();

    // Module with infinite loop
    let wat = r#"
        (module
            (func (export "check") (result i32)
                (loop $infinite
                    br $infinite
                )
                i32.const 1
            )
        )
    "#;

    host.load_module("infinite_loop".to_string(), wat.as_bytes()).unwrap();

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
    };

    // Should fail due to fuel exhaustion
    let result = host.execute("infinite_loop", "check", ctx);
    assert!(result.is_err());
}
```

**Coverage**: 13 security tests verifying sandbox isolation.

---

### Benchmarks

Benchmarks measure performance using Criterion.

**Location**: `crates/*/benches/*.rs`

**Run**:

```bash
cargo bench
```

**View Results**: `target/criterion/report/index.html`

**Example**:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_check_simple(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let evaluator = create_test_evaluator();

    c.bench_function("check_simple", |b| {
        b.to_async(&rt).iter(|| async {
            let request = CheckRequest {
                subject: black_box("user:alice".to_string()),
                resource: black_box("doc:readme".to_string()),
                permission: black_box("viewer".to_string()),
                context: None,
            };
            evaluator.check(request).await.unwrap()
        });
    });
}

criterion_group!(benches, bench_check_simple);
criterion_main!(benches);
```

**Benchmarks**:

- IPL parser: <1ms for typical schemas
- Memory backend: <1μs reads, 1M+ ops/sec
- Evaluator: <10μs simple checks, <100μs complex checks
- Cache operations: <100ns hits

---

## Test Fixtures

Use test fixtures for common setup:

**Example** ([`crates/inferadb-core/tests/common/mod.rs`](../crates/inferadb-core/tests/common/mod.rs)):

```rust
pub struct TestFixture {
    store: Arc<dyn TupleStore>,
    evaluator: Arc<Evaluator>,
}

impl TestFixture {
    pub async fn new() -> Self {
        let store: Arc<dyn TupleStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![]));
        let evaluator = Arc::new(Evaluator::new(store.clone(), schema, None));

        Self { store, evaluator }
    }

    pub async fn write_tuple(&self, object: &str, relation: &str, user: &str) {
        self.store.write(vec![Tuple {
            object: object.to_string(),
            relation: relation.to_string(),
            user: user.to_string(),
        }]).await.unwrap();
    }

    pub async fn assert_allowed(&self, subject: &str, resource: &str, permission: &str) {
        let request = CheckRequest {
            subject: subject.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            context: None,
        };

        let decision = self.evaluator.check(request).await.unwrap();
        assert_eq!(decision, Decision::Allow, "Expected allow for {}/{}/{}", subject, resource, permission);
    }

    pub async fn assert_denied(&self, subject: &str, resource: &str, permission: &str) {
        let request = CheckRequest {
            subject: subject.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            context: None,
        };

        let decision = self.evaluator.check(request).await.unwrap();
        assert_eq!(decision, Decision::Deny, "Expected deny for {}/{}/{}", subject, resource, permission);
    }
}
```

**Usage**:

```rust
#[tokio::test]
async fn test_with_fixture() {
    let fixture = TestFixture::new().await;

    // Write data
    fixture.write_tuple("doc:readme", "viewer", "user:alice").await;

    // Assert expectations
    fixture.assert_allowed("user:alice", "doc:readme", "viewer").await;
    fixture.assert_denied("user:bob", "doc:readme", "viewer").await;
}
```

---

## Test Coverage

Check test coverage with tarpaulin:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Run coverage
cargo tarpaulin --workspace --out Html

# View report
open tarpaulin-report.html
```

**Current Coverage**: >80% across all crates

---

## Running Tests

### All Tests

```bash
cargo test --workspace
```

### Specific Package

```bash
cargo test --package inferadb-core
cargo test --package inferadb-store
cargo test --package inferadb-wasm
```

### Specific Test

```bash
cargo test test_check_allow
cargo test test_check_allow -- --exact
```

### With Output

```bash
cargo test -- --nocapture
cargo test test_check_allow -- --nocapture
```

### Show Ignored Tests

```bash
# List ignored tests
cargo test -- --ignored --list

# Run ignored tests (e.g., FDB tests)
cargo test -- --ignored
```

### Run Tests in Parallel

```bash
# Default: parallel
cargo test

# Sequential (for debugging)
cargo test -- --test-threads=1
```

---

## Writing Tests

### Unit Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        // Arrange
        let input = create_test_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected_value);
    }

    #[tokio::test]
    async fn test_async_feature() {
        // Arrange
        let fixture = setup_async_test().await;

        // Act
        let result = fixture.async_function().await.unwrap();

        // Assert
        assert!(result.is_valid());
    }
}
```

### Integration Test Template

```rust
// tests/my_feature.rs

use inferadb_core::*;

mod common;
use common::TestFixture;

#[tokio::test]
async fn test_my_feature() {
    let fixture = TestFixture::new().await;

    // Set up test data
    fixture.write_tuple("obj:1", "rel", "user:alice").await;

    // Verify behavior
    fixture.assert_allowed("user:alice", "obj:1", "rel").await;
}
```

### Property Test Template

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_feature(
        input in 0..1000i32,
        other in "[a-z]{1,10}",
    ) {
        let result = function_under_test(input, &other);

        // Property: result should always be valid
        prop_assert!(result.is_valid());

        // Property: result should be deterministic
        let result2 = function_under_test(input, &other);
        prop_assert_eq!(result, result2);
    }
}
```

---

## Test Best Practices

### 1. Write Tests First (TDD)

Write the test before implementing the feature:

```rust
#[test]
#[ignore]  // Mark as ignored until implemented
fn test_new_feature() {
    // Write test first
    assert_eq!(new_feature(), expected_result);
}
```

### 2. Use Descriptive Names

Test names should describe what they test:

```rust
// Good
#[test]
fn test_check_allows_direct_tuple() { ... }

// Avoid
#[test]
fn test1() { ... }
```

### 3. Arrange-Act-Assert Pattern

Structure tests clearly:

```rust
#[test]
fn test_feature() {
    // Arrange - set up test data
    let input = create_input();

    // Act - execute the code under test
    let result = function(input);

    // Assert - verify expectations
    assert_eq!(result, expected);
}
```

### 4. Test Edge Cases

Don't just test happy paths:

```rust
#[test]
fn test_empty_input() { ... }

#[test]
fn test_maximum_input() { ... }

#[test]
fn test_invalid_input() { ... }
```

### 5. Use Property Tests for Invariants

Test properties that should always hold:

```rust
proptest! {
    #[test]
    fn prop_idempotent(input in any::<String>()) {
        // Property: calling twice should be same as calling once
        let result1 = normalize(&input);
        let result2 = normalize(&result1);
        prop_assert_eq!(result1, result2);
    }
}
```

### 6. Keep Tests Fast

- Use in-memory backends for tests
- Avoid network I/O
- Use fixtures to share setup
- Run expensive tests only when needed

```rust
#[test]
#[ignore]  // Ignore slow tests by default
fn test_expensive_operation() { ... }
```

---

## Continuous Integration

InferaDB uses GitHub Actions for CI:

**.github/workflows/test.yml**:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Run tests
        run: cargo test --workspace --all-features

      - name: Run benchmarks (check only)
        run: cargo bench --no-run

      - name: Run clippy
        run: cargo clippy -- -D warnings

      - name: Check formatting
        run: cargo fmt --check
```

---

## Debugging Tests

### Print Debug Output

```rust
#[test]
fn test_with_debug() {
    let value = compute_value();
    dbg!(&value);  // Print debug output
    assert_eq!(value, expected);
}
```

### Run with Output

```bash
cargo test test_name -- --nocapture
```

### Run with Logs

```bash
RUST_LOG=debug cargo test test_name -- --nocapture
```

### Use a Debugger

```bash
# In VS Code with rust-analyzer
# Set breakpoint and press F5

# Or use lldb/gdb
cargo test test_name --no-run
lldb target/debug/deps/my_test-<hash>
```

---

## Test Metrics

Current test statistics:

- **Total tests**: 239
  - Unit tests: 204
  - Integration tests: 25
  - Property tests: 8
  - Fuzz tests: 22
  - Security tests: 13
- **Test coverage**: >80%
- **Test execution time**: <10 seconds

---

## Next Steps

- [Building from Source](building.md) - Set up development environment
- [Contributing Guidelines](../CONTRIBUTING.md) - Contribute tests
- [API Reference](api-rest.md) - Test API endpoints
- [Architecture Overview](architecture.md) - Understand system design
