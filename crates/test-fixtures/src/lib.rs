//! Test fixtures for InferaDB integration tests.
//!
//! This crate provides shared test utilities for InferaDB's test suites. It offers
//! a consistent foundation for writing tests across all Engine crates.
//!
//! # Modules
//!
//! - [`proptest_config`] - Environment-aware proptest configuration with tier support
//! - [`tier`] - Test tier detection (`fast`, `standard`, `full`) via Cargo features
//! - [`smoke`] - Deterministic smoke test runners with fixed seeds
//! - [`shared`] - Thread-safe shared fixtures (schemas, constants)
//! - [`internal_jwt`] - JWT generation for testing authentication
//! - [`relationships`] - Test relationship builders
//!
//! # Test Tiers
//!
//! InferaDB uses a three-tier test system controlled by Cargo features:
//!
//! | Tier | Feature | Proptest Cases | Use Case |
//! |------|---------|----------------|----------|
//! | Fast | `test-fast` | 10 | PR checks, pre-commit |
//! | Standard | (default) | 50 | Regular CI, local dev |
//! | Full | `test-full` | 500 | Nightly, release validation |
//!
//! # Usage Examples
//!
//! ## Property-based tests with TestRunner
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::proptest_config::proptest_config;
//! use proptest::prelude::*;
//! use proptest::test_runner::TestRunner;
//!
//! #[test]
//! fn fuzz_my_function() {
//!     let mut runner = TestRunner::new(proptest_config());
//!     runner.run(&any::<u32>(), |input| {
//!         // Test logic
//!         Ok(())
//!     }).expect("proptest failed");
//! }
//! ```
//!
//! ## Smoke tests with deterministic seeds
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::smoke::{smoke_runner, SMOKE_ITERATIONS};
//! use proptest::prelude::*;
//!
//! #[test]
//! fn smoke_my_function() {
//!     let mut runner = smoke_runner();
//!     runner.run(&any::<u32>(), |input| {
//!         // Same logic as fuzz test, runs with fixed seed
//!         Ok(())
//!     }).expect("smoke test failed");
//! }
//! ```
//!
//! ## Tier-aware test behavior
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::tier;
//!
//! #[test]
//! fn my_test() {
//!     let iterations = if tier::is_fast() { 10 } else { 100 };
//!     for _ in 0..iterations {
//!         // Test logic
//!     }
//! }
//! ```
//!
//! # Shared vs Fresh Fixtures
//!
//! - **Safe to share**: Schemas, vault IDs, constants (immutable)
//! - **Must be fresh**: Stores, evaluators (mutable state)
//!
//! See [`shared`] module documentation for thread-safe fixture patterns.

#![deny(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod internal_jwt;
pub mod proptest_config;
pub mod relationships;
pub mod shared;
pub mod smoke;
pub mod tier;

pub use internal_jwt::{
    InternalClaims, InternalKeyPair, create_internal_jwks, generate_internal_jwt,
    generate_internal_keypair,
};
pub use relationships::{test_relationship, test_relationship_with_vault};
