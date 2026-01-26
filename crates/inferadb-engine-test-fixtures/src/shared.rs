//! Shared test fixtures with lazy initialization.
//!
//! This module provides shared, lazily-initialized test fixtures that can be safely
//! reused across multiple tests. Using shared fixtures reduces redundant initialization
//! overhead and improves test execution time.
//!
//! # Thread Safety
//!
//! All shared fixtures are `Send + Sync` and use `OnceLock` for thread-safe lazy
//! initialization. Multiple tests can safely access these fixtures concurrently.
//!
//! # What Can Be Shared vs. What Requires Fresh Instances
//!
//! ## Safe to Share (Read-Only)
//!
//! - **Schemas**: Immutable after creation, safe for concurrent reads
//! - **Vault IDs**: Just `i64` constants, trivially shareable
//! - **Type definitions**: Immutable configuration data
//!
//! ## Requires Fresh Instances (Mutable State)
//!
//! - **Stores**: Tests that write/delete relationships need isolated storage
//! - **Evaluators**: May hold mutable state (caches) or test-specific configuration
//! - **WASM hosts**: May have test-specific module registrations
//!
//! # Usage
//!
//! ```no_run
//! use inferadb_engine_test_fixtures::shared::{
//!     simple_schema, complex_schema,
//!     DEFAULT_VAULT_ID, VAULT_A, VAULT_B,
//! };
//!
//! // Get shared schema (initialized once, reused across tests)
//! let schema = simple_schema();
//!
//! // Use predefined vault IDs for consistency
//! let vault = DEFAULT_VAULT_ID;
//! ```

use std::sync::{Arc, OnceLock};

use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

// =============================================================================
// Vault IDs
// =============================================================================

/// Default vault ID for single-tenant tests.
///
/// Use this when vault isolation is not being tested.
pub const DEFAULT_VAULT_ID: i64 = 0;

/// Standard vault ID for multi-tenant test scenarios (vault A).
pub const VAULT_A: i64 = 11111111111111i64;

/// Standard vault ID for multi-tenant test scenarios (vault B).
pub const VAULT_B: i64 = 22222222222222i64;

/// Standard vault ID for multi-tenant test scenarios (vault C).
pub const VAULT_C: i64 = 33333333333333i64;

/// Standard organization ID for organization tests.
pub const ORG_A: i64 = 99999999999991i64;

/// Standard organization ID for organization tests.
pub const ORG_B: i64 = 99999999999992i64;

// =============================================================================
// Shared Schemas
// =============================================================================

/// Returns a shared reference to a simple test schema.
///
/// This schema contains a single `doc` type with `viewer` relation.
/// Suitable for basic permission check tests.
///
/// # Schema Structure
///
/// ```text
/// type doc
///   relation viewer: this
/// ```
///
/// # Thread Safety
///
/// The schema is lazily initialized on first call and safely shared
/// across all subsequent calls from any thread.
#[must_use]
pub fn simple_schema() -> &'static Arc<Schema> {
    static SCHEMA: OnceLock<Arc<Schema>> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![RelationDef::new("viewer".to_string(), Some(RelationExpr::This))],
        )]))
    })
}

/// Returns a shared reference to a complex test schema.
///
/// This schema contains a `doc` type with `viewer`, `editor`, and `admin`
/// relations demonstrating union and computed usersets.
///
/// # Schema Structure
///
/// ```text
/// type doc
///   relation viewer: this
///   relation editor: this
///   relation admin: this | editor
/// ```
///
/// Admin inherits from editor, demonstrating computed usersets.
///
/// # Thread Safety
///
/// The schema is lazily initialized on first call and safely shared
/// across all subsequent calls from any thread.
#[must_use]
pub fn complex_schema() -> &'static Arc<Schema> {
    static SCHEMA: OnceLock<Arc<Schema>> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("viewer".to_string(), Some(RelationExpr::This)),
                RelationDef::new("editor".to_string(), Some(RelationExpr::This)),
                RelationDef::new(
                    "admin".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                    ])),
                ),
            ],
        )]))
    })
}

/// Returns a shared reference to a multi-type test schema.
///
/// This schema contains `user`, `group`, and `doc` types with
/// hierarchical relationships.
///
/// # Schema Structure
///
/// ```text
/// type user
///
/// type group
///   relation member: this
///
/// type doc
///   relation owner: this
///   relation editor: this | owner | group#member
///   relation viewer: this | editor
/// ```
///
/// # Thread Safety
///
/// The schema is lazily initialized on first call and safely shared
/// across all subsequent calls from any thread.
#[must_use]
pub fn hierarchical_schema() -> &'static Arc<Schema> {
    static SCHEMA: OnceLock<Arc<Schema>> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        Arc::new(Schema::new(vec![
            // User type (no relations - just identity)
            TypeDef::new("user".to_string(), vec![]),
            // Group type
            TypeDef::new(
                "group".to_string(),
                vec![RelationDef::new("member".to_string(), Some(RelationExpr::This))],
            ),
            // Doc type with hierarchical permissions
            TypeDef::new(
                "doc".to_string(),
                vec![
                    RelationDef::new("owner".to_string(), Some(RelationExpr::This)),
                    RelationDef::new(
                        "editor".to_string(),
                        Some(RelationExpr::Union(vec![
                            RelationExpr::This,
                            RelationExpr::RelationRef { relation: "owner".to_string() },
                            RelationExpr::RelatedObjectUserset {
                                relationship: "parent".to_string(),
                                computed: "member".to_string(),
                            },
                        ])),
                    ),
                    RelationDef::new(
                        "viewer".to_string(),
                        Some(RelationExpr::Union(vec![
                            RelationExpr::This,
                            RelationExpr::RelationRef { relation: "editor".to_string() },
                        ])),
                    ),
                ],
            ),
        ]))
    })
}

/// Returns a shared reference to an empty schema.
///
/// Useful for tests that don't need any type definitions or
/// that will dynamically add types.
#[must_use]
pub fn empty_schema() -> &'static Arc<Schema> {
    static SCHEMA: OnceLock<Arc<Schema>> = OnceLock::new();
    SCHEMA.get_or_init(|| Arc::new(Schema::new(vec![])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_ids_are_unique() {
        assert_ne!(VAULT_A, VAULT_B);
        assert_ne!(VAULT_B, VAULT_C);
        assert_ne!(VAULT_A, VAULT_C);
        assert_ne!(ORG_A, ORG_B);
    }

    #[test]
    fn test_simple_schema_initialization() {
        let schema = simple_schema();
        assert_eq!(schema.types.len(), 1);
        assert!(schema.types.iter().any(|t| t.name == "doc"));
    }

    #[test]
    fn test_simple_schema_is_same_instance() {
        let schema1 = simple_schema();
        let schema2 = simple_schema();
        assert!(Arc::ptr_eq(schema1, schema2));
    }

    #[test]
    fn test_complex_schema_has_expected_relations() {
        let schema = complex_schema();
        let doc_type = schema.types.iter().find(|t| t.name == "doc").expect("doc type");
        assert!(doc_type.relations.iter().any(|r| r.name == "viewer"));
        assert!(doc_type.relations.iter().any(|r| r.name == "editor"));
        assert!(doc_type.relations.iter().any(|r| r.name == "admin"));
    }

    #[test]
    fn test_complex_schema_is_same_instance() {
        let schema1 = complex_schema();
        let schema2 = complex_schema();
        assert!(Arc::ptr_eq(schema1, schema2));
    }

    #[test]
    fn test_hierarchical_schema_has_multiple_types() {
        let schema = hierarchical_schema();
        assert!(schema.types.len() >= 2);
        assert!(schema.types.iter().any(|t| t.name == "doc"));
        assert!(schema.types.iter().any(|t| t.name == "group"));
    }

    #[test]
    fn test_empty_schema_has_no_types() {
        let schema = empty_schema();
        assert!(schema.types.is_empty());
    }

    #[test]
    fn test_schemas_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<Schema>>();
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(|| {
                    let s1 = simple_schema();
                    let s2 = complex_schema();
                    let s3 = hierarchical_schema();
                    // Cast to usize for Send safety (raw pointers aren't Send)
                    (Arc::as_ptr(s1) as usize, Arc::as_ptr(s2) as usize, Arc::as_ptr(s3) as usize)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All threads should see the same Arc instances
        let first = &results[0];
        for result in &results[1..] {
            assert_eq!(first.0, result.0, "simple_schema should be same instance");
            assert_eq!(first.1, result.1, "complex_schema should be same instance");
            assert_eq!(first.2, result.2, "hierarchical_schema should be same instance");
        }
    }
}
