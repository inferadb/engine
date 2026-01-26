//! Smoke test helpers for property-based tests.
//!
//! This module provides utilities for creating deterministic "smoke" versions of
//! property-based tests. Smoke tests use fixed seeds and minimal iterations to
//! verify code paths quickly, while full fuzz tests run with many iterations.
//!
//! # Smoke vs Fuzz Testing Pattern
//!
//! | Test Type | Iterations | Seed | Use Case |
//! |-----------|------------|------|----------|
//! | Smoke | 5 | Fixed | Default CI, quick verification |
//! | Fuzz | 50-500 | Random | Full coverage, nightly runs |
//!
//! # Usage
//!
//! Smoke tests sample from the same strategies as fuzz tests but with
//! deterministic seeds:
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::smoke::{SMOKE_ITERATIONS, smoke_runner};
//! use proptest::prelude::*;
//!
//! #[test]
//! fn smoke_my_operation() {
//!     let mut runner = smoke_runner();
//!     runner.run(&any::<u32>(), |value| {
//!         // Same test logic as fuzz test
//!         assert!(value < u32::MAX);
//!         Ok(())
//!     }).expect("smoke test failed");
//! }
//!
//! // Full fuzz test gated behind test-full feature
//! #[test]
//! #[cfg(feature = "test-full")]
//! fn fuzz_my_operation() {
//!     // Full proptest implementation
//! }
//! ```

use proptest::test_runner::{Config as ProptestConfig, TestRunner};

/// Number of iterations for smoke tests.
///
/// Smoke tests run a minimal number of iterations (5) with fixed seeds
/// to quickly verify code paths without the overhead of full fuzzing.
pub const SMOKE_ITERATIONS: u32 = 5;

/// Fixed seed for deterministic smoke test execution.
///
/// Using a fixed seed ensures smoke tests are reproducible across runs.
/// The seed value is arbitrary but chosen to provide reasonable coverage
/// of typical input distributions.
pub const SMOKE_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Creates a proptest configuration for smoke tests.
///
/// Returns a configuration with:
/// - Fixed number of cases ([`SMOKE_ITERATIONS`])
/// - Deterministic seed for reproducibility
///
/// # Examples
///
/// ```no_run
/// use inferadb_engine_test_fixtures::smoke::smoke_config;
/// use proptest::test_runner::TestRunner;
///
/// let mut runner = TestRunner::new(smoke_config());
/// ```
#[must_use]
pub fn smoke_config() -> ProptestConfig {
    ProptestConfig { cases: SMOKE_ITERATIONS, ..ProptestConfig::default() }
}

/// Creates a test runner configured for smoke tests.
///
/// The runner uses a fixed seed for deterministic execution and runs
/// only [`SMOKE_ITERATIONS`] cases. This makes smoke tests fast and
/// reproducible.
///
/// # Examples
///
/// ```no_run
/// use inferadb_engine_test_fixtures::smoke::smoke_runner;
/// use proptest::prelude::*;
///
/// let mut runner = smoke_runner();
/// runner.run(&any::<u32>(), |value| {
///     // test logic
///     Ok(())
/// }).expect("smoke test failed");
/// ```
#[must_use]
pub fn smoke_runner() -> TestRunner {
    TestRunner::new_with_rng(
        smoke_config(),
        proptest::test_runner::TestRng::from_seed(
            proptest::test_runner::RngAlgorithm::ChaCha,
            &SMOKE_SEED,
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn test_smoke_runner_is_deterministic() {
        // Run twice with same seed, should produce same sequence
        let mut runner1 = smoke_runner();
        let mut runner2 = smoke_runner();

        // Use RefCell for interior mutability since TestRunner::run requires Fn, not FnMut
        let values1 = RefCell::new(Vec::new());
        let values2 = RefCell::new(Vec::new());

        runner1
            .run(&(0u32..1000), |v| {
                values1.borrow_mut().push(v);
                Ok(())
            })
            .expect("runner1 failed");

        runner2
            .run(&(0u32..1000), |v| {
                values2.borrow_mut().push(v);
                Ok(())
            })
            .expect("runner2 failed");

        let values1 = values1.into_inner();
        let values2 = values2.into_inner();

        assert_eq!(values1, values2, "Smoke runners should be deterministic");
        assert_eq!(values1.len(), SMOKE_ITERATIONS as usize);
    }

    #[test]
    fn test_smoke_config_has_correct_iterations() {
        let config = smoke_config();
        assert_eq!(config.cases, SMOKE_ITERATIONS);
    }
}
