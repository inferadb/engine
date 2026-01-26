//! Test fixtures for InferaDB integration tests
//!
//! This crate provides shared test utilities for internal JWTs, mock JWKS servers,
//! relationships, and other test fixtures that are used across multiple test suites.

#![deny(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod internal_jwt;
pub mod proptest_config;
pub mod relationships;

pub use internal_jwt::{
    InternalClaims, InternalKeyPair, create_internal_jwks, generate_internal_jwt,
    generate_internal_keypair,
};
pub use relationships::{test_relationship, test_relationship_with_vault};
