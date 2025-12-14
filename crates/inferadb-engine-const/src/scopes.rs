//! Scope constants for InferaDB authorization
//!
//! This module defines all valid scopes for authentication and authorization.
//! Scopes control what operations a client can perform.
//!
//! ## Scope Hierarchy
//!
//! - **inferadb.admin**: Full administrative access (implies all other scopes)
//! - **inferadb.check**: Authorization checks and policy evaluation
//! - **inferadb.expand**: Relationship tree expansion
//! - **inferadb.write**: Create, update, delete relationships
//! - **inferadb.read**: Read-only access to relationships
//! - **inferadb.list**: List resources, subjects, and relationships
//! - **inferadb.watch**: Real-time change notifications
//! - **inferadb.simulate**: Ephemeral policy evaluation
//!
//! ## Examples
//!
//! ```rust
//! use inferadb_engine_const::scopes::*;
//!
//! // Check if user has admin scope
//! let user_scopes = vec!["inferadb.admin", "inferadb.check"];
//! let has_admin = user_scopes.contains(&SCOPE_ADMIN);
//! assert!(has_admin);
//!
//! // Require multiple scopes
//! let required = vec![SCOPE_CHECK, SCOPE_EXPAND];
//! assert_eq!(required, vec!["inferadb.check", "inferadb.expand"]);
//! ```

// ============================================================================
// Core Operation Scopes
// ============================================================================

/// Scope for authorization checks and policy evaluation
///
/// Required for:
/// - `POST /v1/evaluate` - Check if subject has permission on resource
/// - `POST /v1/expand` - Expand relationship trees (alternative to SCOPE_EXPAND)
/// - `POST /v1/simulate` - Simulate policy evaluation
/// - AuthZEN `/access/v1/evaluation/evaluate` endpoint
pub const SCOPE_CHECK: &str = "inferadb.check";

/// Scope for writing relationships
///
/// Required for:
/// - `POST /v1/relationships/write` - Batch write relationships
/// - `DELETE /v1/relationships/:id` - Delete single relationship
/// - `POST /v1/relationships/delete` - Bulk delete relationships
pub const SCOPE_WRITE: &str = "inferadb.write";

/// Scope for reading relationships
///
/// Required for:
/// - `GET /v1/relationships/:id` - Read single relationship
/// - `POST /v1/relationships/list` - List relationships (alternative to SCOPE_LIST_RELATIONSHIPS)
pub const SCOPE_READ: &str = "inferadb.read";

/// Scope for expanding relationship trees
///
/// Required for:
/// - `POST /v1/expand` - Expand relationship trees and compute usersets
pub const SCOPE_EXPAND: &str = "inferadb.expand";

// ============================================================================
// Listing Scopes
// ============================================================================

/// Generic scope for listing operations
///
/// Required for:
/// - AuthZEN `/access/v1/search` endpoints
/// - Generic list operations when specific list scopes not provided
pub const SCOPE_LIST: &str = "inferadb.list";

/// Scope for listing relationships
///
/// Required for:
/// - `POST /v1/relationships/list` - List relationships matching filters
pub const SCOPE_LIST_RELATIONSHIPS: &str = "inferadb.list-relationships";

/// Scope for listing subjects
///
/// Required for:
/// - `POST /v1/subjects/list` - List subjects for a given resource and permission
pub const SCOPE_LIST_SUBJECTS: &str = "inferadb.list-subjects";

/// Scope for listing resources
///
/// Required for:
/// - `POST /v1/resources/list` - List resources accessible by a subject
pub const SCOPE_LIST_RESOURCES: &str = "inferadb.list-resources";

// ============================================================================
// Real-Time and Simulation Scopes
// ============================================================================

/// Scope for watching real-time relationship changes
///
/// Required for:
/// - `POST /v1/watch` - Subscribe to relationship change stream
pub const SCOPE_WATCH: &str = "inferadb.watch";

/// Scope for ephemeral policy evaluation
///
/// Required for:
/// - `POST /v1/simulate` - Evaluate policies with temporary relationships
pub const SCOPE_SIMULATE: &str = "inferadb.simulate";

// ============================================================================
// Administrative Scopes
// ============================================================================

/// Scope for all administrative operations
///
/// Required for:
/// - `POST /v1/accounts` - Create accounts
/// - `GET /v1/accounts` - List all accounts
/// - `GET /v1/accounts/:id` - View any account
/// - `PATCH /v1/accounts/:id` - Update accounts
/// - `DELETE /v1/accounts/:id` - Delete accounts
/// - `POST /v1/accounts/:account_id/vaults` - Create vaults for any account
/// - `GET /v1/accounts/:account_id/vaults` - List vaults for any account
/// - `GET /v1/vaults/:id` - View any vault
/// - `PATCH /v1/vaults/:id` - Update any vault
/// - `DELETE /v1/vaults/:id` - Delete any vault
///
/// Note: Admin scope grants access to cross-account operations
pub const SCOPE_ADMIN: &str = "inferadb.admin";

/// Scope for account/organization management
///
/// Required for organization-level operations when not using admin scope:
/// - `GET /v1/organizations/:id` - View organization details (own organization)
/// - `PATCH /v1/organizations/:id` - Update organization (own organization)
/// - `DELETE /v1/organizations/:id` - Delete organization (own organization)
///
/// This scope provides the same capabilities as admin for resources the caller owns,
/// without granting cross-organization access.
pub const SCOPE_ACCOUNT_MANAGE: &str = "inferadb.account.manage";

/// Scope for vault management
///
/// Required for vault-level operations when not using admin scope:
/// - `POST /v1/organizations/:org/vaults` - Create vault (own organization)
/// - `GET /v1/vaults/:id` - View vault details (own organization's vaults)
/// - `PATCH /v1/vaults/:id` - Update vault (own organization's vaults)
/// - `DELETE /v1/vaults/:id` - Delete vault (own organization's vaults)
///
/// This scope provides vault management capabilities within the caller's organization,
/// without granting cross-organization access.
pub const SCOPE_VAULT_MANAGE: &str = "inferadb.vault.manage";

// ============================================================================
// Scope Validation Helpers
// ============================================================================

/// All valid scopes in the system
///
/// Used for validation and documentation generation
pub const ALL_SCOPES: &[&str] = &[
    SCOPE_CHECK,
    SCOPE_WRITE,
    SCOPE_READ,
    SCOPE_EXPAND,
    SCOPE_LIST,
    SCOPE_LIST_RELATIONSHIPS,
    SCOPE_LIST_SUBJECTS,
    SCOPE_LIST_RESOURCES,
    SCOPE_WATCH,
    SCOPE_SIMULATE,
    SCOPE_ADMIN,
    SCOPE_ACCOUNT_MANAGE,
    SCOPE_VAULT_MANAGE,
];

/// Check if a scope string is valid
///
/// # Examples
///
/// ```
/// use inferadb_engine_const::scopes::{is_valid_scope, SCOPE_CHECK};
///
/// assert!(is_valid_scope(SCOPE_CHECK));
/// assert!(is_valid_scope("inferadb.check"));
/// assert!(!is_valid_scope("invalid.scope"));
/// ```
pub fn is_valid_scope(scope: &str) -> bool {
    ALL_SCOPES.contains(&scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_constants_are_valid() {
        for scope in ALL_SCOPES {
            assert!(is_valid_scope(scope), "Scope '{}' should be valid", scope);
        }
    }

    #[test]
    fn test_scope_format() {
        // All scopes should start with "inferadb."
        for scope in ALL_SCOPES {
            assert!(
                scope.starts_with("inferadb."),
                "Scope '{}' should start with 'inferadb.'",
                scope
            );
        }
    }

    #[test]
    fn test_is_valid_scope() {
        assert!(is_valid_scope(SCOPE_CHECK));
        assert!(is_valid_scope(SCOPE_ADMIN));
        assert!(is_valid_scope(SCOPE_WRITE));
        assert!(!is_valid_scope("invalid"));
        assert!(!is_valid_scope("inferadb.invalid"));
    }

    #[test]
    fn test_no_duplicate_scopes() {
        let mut unique_scopes = std::collections::HashSet::new();
        for scope in ALL_SCOPES {
            assert!(unique_scopes.insert(scope), "Duplicate scope found: '{}'", scope);
        }
    }
}
