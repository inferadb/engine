//! Test tier detection and configuration.
//!
//! This module provides compile-time and runtime detection of the active test tier,
//! allowing test code to adjust behavior based on whether it's running in fast,
//! standard, or full mode.
//!
//! # Test Tiers
//!
//! | Tier     | Feature Flag  | Proptest Cases | Ignored Tests | Use Case                    |
//! |----------|---------------|----------------|---------------|-----------------------------|
//! | Fast     | `test-fast`   | 10             | Excluded      | PR checks, pre-commit       |
//! | Standard | (default)     | 50             | Excluded      | Regular CI, local dev       |
//! | Full     | `test-full`   | 500            | Included      | Nightly, release validation |
//!
//! # Usage
//!
//! ## Compile-time tier detection
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::tier;
//!
//! if tier::is_fast() {
//!     // Minimal test setup
//! } else if tier::is_full() {
//!     // Comprehensive test setup
//! }
//! ```
//!
//! ## Runtime tier detection
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::tier::{Tier, current_tier};
//!
//! match current_tier() {
//!     Tier::Fast => println!("Running fast tests"),
//!     Tier::Standard => println!("Running standard tests"),
//!     Tier::Full => println!("Running full tests"),
//! }
//! ```
//!
//! # Conditional Compilation
//!
//! Use the tier functions to conditionally include expensive test setup:
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::tier;
//!
//! #[test]
//! fn my_test() {
//!     if tier::is_full() {
//!         // Include expensive setup only in full tier
//!         // run_expensive_setup();
//!     }
//!     // Common test logic
//! }
//! ```

/// Test execution tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Fast tier: minimal iterations, PR checks, pre-commit hooks.
    Fast,
    /// Standard tier: balanced coverage, regular CI, local development.
    Standard,
    /// Full tier: comprehensive coverage, nightly runs, release validation.
    Full,
}

impl Tier {
    /// Returns the recommended proptest case count for this tier.
    #[must_use]
    pub const fn proptest_cases(self) -> u32 {
        match self {
            Self::Fast => 10,
            Self::Standard => 50,
            Self::Full => 500,
        }
    }

    /// Returns the tier name as a static string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Returns `true` if the `test-fast` feature is enabled.
///
/// Use this for compile-time conditional compilation:
///
/// ```no_run
/// use inferadb_engine_test_fixtures::tier;
///
/// if tier::is_fast() {
///     // Skip expensive setup
/// }
/// ```
#[must_use]
pub const fn is_fast() -> bool {
    cfg!(feature = "test-fast")
}

/// Returns `true` if the `test-full` feature is enabled.
///
/// Use this for compile-time conditional compilation:
///
/// ```no_run
/// use inferadb_engine_test_fixtures::tier;
///
/// if tier::is_full() {
///     // Include expensive setup
/// }
/// ```
#[must_use]
pub const fn is_full() -> bool {
    cfg!(feature = "test-full")
}

/// Returns `true` if running in standard tier (neither fast nor full).
#[must_use]
pub const fn is_standard() -> bool {
    !is_fast() && !is_full()
}

/// Returns the currently active test tier based on feature flags.
///
/// Priority: `test-full` > `test-fast` > standard (default)
///
/// If both features are enabled (which shouldn't happen), `test-full` takes precedence.
#[must_use]
pub const fn current_tier() -> Tier {
    if is_full() {
        Tier::Full
    } else if is_fast() {
        Tier::Fast
    } else {
        Tier::Standard
    }
}

/// Returns the recommended proptest case count for the current tier.
///
/// This can be overridden by the `PROPTEST_CASES` environment variable.
/// Use [`crate::proptest_config::test_cases()`] for the final case count
/// that respects environment overrides.
#[must_use]
pub const fn tier_proptest_cases() -> u32 {
    current_tier().proptest_cases()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_proptest_cases() {
        assert_eq!(Tier::Fast.proptest_cases(), 10);
        assert_eq!(Tier::Standard.proptest_cases(), 50);
        assert_eq!(Tier::Full.proptest_cases(), 500);
    }

    #[test]
    fn test_tier_names() {
        assert_eq!(Tier::Fast.name(), "fast");
        assert_eq!(Tier::Standard.name(), "standard");
        assert_eq!(Tier::Full.name(), "full");
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(format!("{}", Tier::Fast), "fast");
        assert_eq!(format!("{}", Tier::Standard), "standard");
        assert_eq!(format!("{}", Tier::Full), "full");
    }

    #[test]
    fn test_current_tier_consistency() {
        // At least one of these should be true
        let tier = current_tier();
        assert!(
            matches!(tier, Tier::Fast | Tier::Standard | Tier::Full),
            "current_tier should return a valid tier"
        );
    }

    #[test]
    fn test_tier_detection_mutually_exclusive() {
        // Standard is mutually exclusive with fast and full
        if is_standard() {
            assert!(!is_fast());
            assert!(!is_full());
        }
    }

    #[test]
    fn test_tier_proptest_cases_matches_current_tier() {
        assert_eq!(tier_proptest_cases(), current_tier().proptest_cases());
    }
}
