//! Shared proptest configuration for InferaDB test suites.
//!
//! This module provides a centralized configuration for property-based tests,
//! allowing consistent case counts across all test suites and environment-aware
//! adjustment for CI, local development, and nightly test runs.
//!
//! # Environment Variable
//!
//! The `PROPTEST_CASES` environment variable controls the number of test cases:
//!
//! | Environment | Value | Use Case |
//! |-------------|-------|----------|
//! | CI (PRs)    | 25    | Fast feedback on pull requests |
//! | Local dev   | 50    | Default balance of speed and coverage |
//! | Nightly     | 500   | Comprehensive fuzzing for releases |
//!
//! # Usage
//!
//! For tests using `TestRunner` directly (recommended for async tests):
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::proptest_config::proptest_config;
//! use proptest::test_runner::TestRunner;
//!
//! let mut runner = TestRunner::new(proptest_config());
//! runner.run(&strategy, |input| {
//!     // test logic
//!     Ok(())
//! }).expect("proptest failed");
//! ```
//!
//! For tests using the `proptest!` macro:
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::proptest_config::test_cases;
//! use proptest::prelude::*;
//!
//! proptest! {
//!     #![proptest_config(ProptestConfig::with_cases(test_cases()))]
//!     
//!     #[test]
//!     fn my_property_test(input in any::<u32>()) {
//!         // test logic
//!     }
//! }
//! ```

use proptest::test_runner::Config as ProptestConfig;

/// Default number of proptest cases for local development.
///
/// This value balances thoroughness with execution speed for day-to-day development.
pub const DEFAULT_PROPTEST_CASES: u32 = 50;

/// Returns the number of test cases to run, reading from `PROPTEST_CASES` environment variable.
///
/// Defaults to [`DEFAULT_PROPTEST_CASES`] (50) if the environment variable is not set or invalid.
///
/// # Examples
///
/// ```
/// use inferadb_engine_test_fixtures::proptest_config::test_cases;
///
/// // Returns 50 by default, or the value of PROPTEST_CASES if set
/// let cases = test_cases();
/// assert!(cases > 0);
/// ```
#[must_use]
pub fn test_cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PROPTEST_CASES)
}

/// Returns a proptest configuration with the appropriate number of test cases.
///
/// This is the recommended way to configure `TestRunner` for property-based tests.
/// The case count is determined by the `PROPTEST_CASES` environment variable,
/// defaulting to [`DEFAULT_PROPTEST_CASES`] for local development.
///
/// # Examples
///
/// ```no_run
/// use inferadb_engine_test_fixtures::proptest_config::proptest_config;
/// use proptest::test_runner::TestRunner;
///
/// let mut runner = TestRunner::new(proptest_config());
/// ```
#[must_use]
pub fn proptest_config() -> ProptestConfig {
    ProptestConfig::with_cases(test_cases())
}

// Re-export for convenience
pub use proptest::test_runner::Config;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cases() {
        // When PROPTEST_CASES is not set, should return default
        // Note: This test may fail if PROPTEST_CASES is set in the environment
        let cases = test_cases();
        assert!(cases > 0, "test_cases should return a positive number");
    }

    #[test]
    fn test_proptest_config_creation() {
        let config = proptest_config();
        assert!(config.cases > 0, "proptest_config should have positive cases");
    }
}
