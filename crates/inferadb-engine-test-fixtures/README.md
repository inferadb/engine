# inferadb-engine-test-fixtures

Shared test utilities for InferaDB Engine integration tests.

## Modules

### proptest_config

Centralized property-based test configuration with environment-aware case counts.

**Usage with `TestRunner` (recommended for async tests):**

```rust
use inferadb_engine_test_fixtures::proptest_config::proptest_config;
use proptest::test_runner::TestRunner;

let mut runner = TestRunner::new(proptest_config());
runner.run(&strategy, |input| {
    // test logic
    Ok(())
}).expect("proptest failed");
```

**Usage with `proptest!` macro:**

```rust
use inferadb_engine_test_fixtures::proptest_config::test_cases;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(test_cases()))]
    
    #[test]
    fn my_test(input in any::<u32>()) {
        // test logic
    }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROPTEST_CASES` | 50 | Number of test cases per property test |

**Recommended values by environment:**

| Environment | Value | Use Case |
|-------------|-------|----------|
| CI (PRs) | 25 | Fast feedback on pull requests |
| Local dev | 50 | Default balance of speed and coverage |
| Nightly | 500 | Comprehensive fuzzing for releases |

### internal_jwt

Utilities for generating internal JWTs and JWKS for testing authentication flows.

### relationships

Helper functions for creating test relationships and fixtures.
