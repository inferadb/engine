//! Test fixtures for InferaDB integration tests
//!
//! This crate provides shared test utilities for internal JWTs, mock JWKS servers,
//! and other test fixtures that are used across multiple test suites.

pub mod internal_jwt;

pub use internal_jwt::{
    InternalClaims,
    InternalKeyPair,
    generate_internal_keypair,
    generate_internal_jwt,
    create_internal_jwks,
};
