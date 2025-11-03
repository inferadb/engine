//! Integration test entry point
//!
//! This module serves as the entry point for the integration test suite.
//! It includes the integration test framework and test files.

#[path = "integration/mod.rs"]
mod framework;

#[path = "integration/e2e_tests.rs"]
mod e2e_tests;

#[path = "integration/failure_tests.rs"]
mod failure_tests;

pub use framework::*;
