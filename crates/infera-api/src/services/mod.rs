//! Service layer for InferaDB API
//!
//! This module contains the business logic layer that sits between protocol handlers
//! (gRPC, REST, AuthZEN) and the core evaluation engine. Services handle:
//!
//! - Vault-scoped evaluator creation for multi-tenant isolation
//! - Request validation
//! - Business logic execution
//! - Protocol-agnostic error handling
//!
//! Protocol handlers are thin adapters that convert between protocol-specific formats
//! and call the appropriate service methods.

pub mod evaluation;
pub mod expansion;
pub mod relationships;
pub mod resources;
pub mod subjects;
pub mod validation;
pub mod watch;

pub use evaluation::EvaluationService;
pub use expansion::ExpansionService;
pub use relationships::RelationshipService;
pub use resources::ResourceService;
pub use subjects::SubjectService;
pub use watch::WatchService;
