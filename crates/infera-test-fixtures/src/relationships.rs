//! Test fixtures for creating relationships
//!
//! Provides helper functions for creating test relationships with sensible defaults.

use infera_types::Relationship;
use uuid::Uuid;

/// Create a test relationship with nil vault (for tests that don't care about multi-tenancy)
///
/// # Example
/// ```
/// use infera_test_fixtures::test_relationship;
///
/// let rel = test_relationship("doc:readme", "viewer", "user:alice");
/// assert_eq!(rel.resource, "doc:readme");
/// ```
pub fn test_relationship(resource: &str, relation: &str, subject: &str) -> Relationship {
    Relationship {
        vault: Uuid::nil(),
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: subject.to_string(),
    }
}

/// Create a test relationship with a specific vault
///
/// # Example
/// ```
/// use infera_test_fixtures::test_relationship_with_vault;
/// use uuid::Uuid;
///
/// let vault = Uuid::new_v4();
/// let rel = test_relationship_with_vault(vault, "doc:readme", "viewer", "user:alice");
/// assert_eq!(rel.vault, vault);
/// ```
pub fn test_relationship_with_vault(
    vault: Uuid,
    resource: &str,
    relation: &str,
    subject: &str,
) -> Relationship {
    Relationship {
        vault,
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: subject.to_string(),
    }
}
