//! Shared proptest configuration for InferaDB test suites.
//!
//! This module provides a centralized configuration for property-based tests,
//! allowing consistent case counts across all test suites and environment-aware
//! adjustment for CI, local development, and nightly test runs.
//!
//! # Test Tiers
//!
//! The default case count is determined by the active test tier (via Cargo features):
//!
//! | Tier     | Feature Flag  | Default Cases | Use Case                    |
//! |----------|---------------|---------------|-----------------------------|
//! | Fast     | `test-fast`   | 10            | PR checks, pre-commit       |
//! | Standard | (default)     | 50            | Regular CI, local dev       |
//! | Full     | `test-full`   | 500           | Nightly, release validation |
//!
//! # Environment Override
//!
//! The `PROPTEST_CASES` environment variable overrides the tier default:
//!
//! ```bash
//! PROPTEST_CASES=100 cargo test  # Override to 100 cases regardless of tier
//! ```
//!
//! # Usage
//!
//! For tests using `TestRunner` directly (recommended for async tests):
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::proptest_config::proptest_config;
//! use proptest::prelude::*;
//! use proptest::test_runner::TestRunner;
//!
//! let strategy = any::<u32>();
//! let mut runner = TestRunner::new(proptest_config());
//! runner.run(&strategy, |_input| {
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

use crate::tier;

/// Default number of proptest cases based on the active test tier.
///
/// - Fast tier (`test-fast` feature): 10 cases
/// - Standard tier (default): 50 cases
/// - Full tier (`test-full` feature): 500 cases
///
/// This value is determined at compile time based on active Cargo features.
pub const DEFAULT_PROPTEST_CASES: u32 = tier::tier_proptest_cases();

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
