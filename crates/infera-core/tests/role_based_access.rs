//! Integration test: Role-based access control scenario
//!
//! This test implements a classic RBAC system with:
//! - Users assigned to roles
//! - Roles granted permissions
//! - Resources with required permissions

use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

mod common;
use common::{TestFixture, relationship};

/// Create a role-based access control schema
fn create_schema() -> Schema {
    Schema::new(vec![
        // Role type
        TypeDef::new(
            "role".to_string(),
            vec![
                RelationDef::new("member".to_string(), None),
                RelationDef::new("parent_role".to_string(), None), // Role hierarchy
                // Users in this role include direct members and members of parent roles
                RelationDef::new(
                    "user".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "member".to_string() },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "parent_role".to_string(),
                            computed: "user".to_string(),
                        },
                    ])),
                ),
            ],
        ),
        // Resource type
        TypeDef::new(
            "resource".to_string(),
            vec![
                RelationDef::new("reader_role".to_string(), None),
                RelationDef::new("writer_role".to_string(), None),
                RelationDef::new("admin_role".to_string(), None),
                // can_read = reader_role->user | writer_role->user | admin_role->user
                RelationDef::new(
                    "can_read".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelatedObjectUserset {
                            relationship: "reader_role".to_string(),
                            computed: "user".to_string(),
                        },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "writer_role".to_string(),
                            computed: "user".to_string(),
                        },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "admin_role".to_string(),
                            computed: "user".to_string(),
                        },
                    ])),
                ),
                // can_write = writer_role->user | admin_role->user
                RelationDef::new(
                    "can_write".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelatedObjectUserset {
                            relationship: "writer_role".to_string(),
                            computed: "user".to_string(),
                        },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "admin_role".to_string(),
                            computed: "user".to_string(),
                        },
                    ])),
                ),
                // can_delete = admin_role->user
                RelationDef::new(
                    "can_delete".to_string(),
                    Some(RelationExpr::RelatedObjectUserset {
                        relationship: "admin_role".to_string(),
                        computed: "user".to_string(),
                    }),
                ),
            ],
        ),
    ])
}

#[tokio::test]
async fn test_basic_role_assignment() {
    let fixture = TestFixture::new(create_schema());

    // Alice is a member of the "readers" role
    // resource1 grants read access to the "readers" role
    fixture
        .write_relationships(vec![
            relationship("role:readers", "member", "user:alice"),
            relationship("resource:resource1", "reader_role", "role:readers"),
        ])
        .await
        .unwrap();

    // Alice can read resource1
    fixture.assert_allowed("user:alice", "resource:resource1", "can_read").await;

    // Alice cannot write
    fixture.assert_denied("user:alice", "resource:resource1", "can_write").await;

    // Alice cannot delete
    fixture.assert_denied("user:alice", "resource:resource1", "can_delete").await;
}

#[tokio::test]
async fn test_writer_role() {
    let fixture = TestFixture::new(create_schema());

    // Bob is a member of the "writers" role
    // resource1 grants write access to the "writers" role
    fixture
        .write_relationships(vec![
            relationship("role:writers", "member", "user:bob"),
            relationship("resource:resource1", "writer_role", "role:writers"),
        ])
        .await
        .unwrap();

    // Bob can read (writers can also read)
    fixture.assert_allowed("user:bob", "resource:resource1", "can_read").await;

    // Bob can write
    fixture.assert_allowed("user:bob", "resource:resource1", "can_write").await;

    // Bob cannot delete
    fixture.assert_denied("user:bob", "resource:resource1", "can_delete").await;
}

#[tokio::test]
async fn test_admin_role() {
    let fixture = TestFixture::new(create_schema());

    // Charlie is a member of the "admins" role
    // resource1 grants admin access to the "admins" role
    fixture
        .write_relationships(vec![
            relationship("role:admins", "member", "user:charlie"),
            relationship("resource:resource1", "admin_role", "role:admins"),
        ])
        .await
        .unwrap();

    // Charlie can read
    fixture.assert_allowed("user:charlie", "resource:resource1", "can_read").await;

    // Charlie can write
    fixture.assert_allowed("user:charlie", "resource:resource1", "can_write").await;

    // Charlie can delete
    fixture.assert_allowed("user:charlie", "resource:resource1", "can_delete").await;
}

#[tokio::test]
async fn test_role_hierarchy() {
    let fixture = TestFixture::new(create_schema());

    // Set up role hierarchy:
    // - "power_users" role has "users" as parent
    // - Alice is member of "users" role
    // - resource1 grants read to "power_users"
    fixture
        .write_relationships(vec![
            relationship("role:power_users", "parent_role", "role:users"),
            relationship("role:users", "member", "user:alice"),
            relationship("resource:resource1", "reader_role", "role:power_users"),
        ])
        .await
        .unwrap();

    // Alice can read through the role hierarchy
    // users -> power_users -> resource1
    fixture.assert_allowed("user:alice", "resource:resource1", "can_read").await;
}

#[tokio::test]
async fn test_multiple_roles_per_user() {
    let fixture = TestFixture::new(create_schema());

    // Bob is a member of both "readers" and "writers" roles
    // resource1 grants read to "readers"
    // resource2 grants write to "writers"
    fixture
        .write_relationships(vec![
            relationship("role:readers", "member", "user:bob"),
            relationship("role:writers", "member", "user:bob"),
            relationship("resource:resource1", "reader_role", "role:readers"),
            relationship("resource:resource2", "writer_role", "role:writers"),
        ])
        .await
        .unwrap();

    // Bob can read resource1 (through readers role)
    fixture.assert_allowed("user:bob", "resource:resource1", "can_read").await;

    // Bob can write resource2 (through writers role)
    fixture.assert_allowed("user:bob", "resource:resource2", "can_write").await;

    // Bob cannot write resource1 (only has reader role)
    fixture.assert_denied("user:bob", "resource:resource1", "can_write").await;
}

#[tokio::test]
async fn test_multiple_roles_per_resource() {
    let fixture = TestFixture::new(create_schema());

    // resource1 grants access to multiple roles
    fixture
        .write_relationships(vec![
            relationship("role:readers", "member", "user:alice"),
            relationship("role:writers", "member", "user:bob"),
            relationship("role:admins", "member", "user:charlie"),
            relationship("resource:resource1", "reader_role", "role:readers"),
            relationship("resource:resource1", "writer_role", "role:writers"),
            relationship("resource:resource1", "admin_role", "role:admins"),
        ])
        .await
        .unwrap();

    // Alice can read
    fixture.assert_allowed("user:alice", "resource:resource1", "can_read").await;

    // Bob can read and write
    fixture.assert_allowed("user:bob", "resource:resource1", "can_read").await;
    fixture.assert_allowed("user:bob", "resource:resource1", "can_write").await;

    // Charlie can do everything
    fixture.assert_allowed("user:charlie", "resource:resource1", "can_read").await;
    fixture.assert_allowed("user:charlie", "resource:resource1", "can_write").await;
    fixture.assert_allowed("user:charlie", "resource:resource1", "can_delete").await;
}

#[tokio::test]
async fn test_no_role_no_access() {
    let fixture = TestFixture::new(create_schema());

    // resource1 exists but has no role assignments
    // Dave has no role assignments
    fixture.write_relationships(vec![]).await.unwrap();

    // Dave cannot access resource1 at all
    fixture.assert_denied("user:dave", "resource:resource1", "can_read").await;
    fixture.assert_denied("user:dave", "resource:resource1", "can_write").await;
    fixture.assert_denied("user:dave", "resource:resource1", "can_delete").await;
}

#[tokio::test]
async fn test_complex_role_hierarchy() {
    let fixture = TestFixture::new(create_schema());

    // Complex hierarchy:
    // - "super_admins" has "admins" as parent
    // - "admins" has "power_users" as parent
    // - "power_users" has "users" as parent
    // - Alice is member of "users"
    // - resource1 grants read to "super_admins"
    fixture
        .write_relationships(vec![
            relationship("role:super_admins", "parent_role", "role:admins"),
            relationship("role:admins", "parent_role", "role:power_users"),
            relationship("role:power_users", "parent_role", "role:users"),
            relationship("role:users", "member", "user:alice"),
            relationship("resource:resource1", "reader_role", "role:super_admins"),
        ])
        .await
        .unwrap();

    // Alice can read through the deep hierarchy
    // users -> power_users -> admins -> super_admins -> resource1
    fixture.assert_allowed("user:alice", "resource:resource1", "can_read").await;
}

#[tokio::test]
async fn test_rbac_with_multiple_users_and_resources() {
    let fixture = TestFixture::new(create_schema());

    // Comprehensive scenario:
    // - 3 roles: readers, writers, admins
    // - 3 resources: public, internal, confidential
    // - 4 users with different role assignments
    fixture
        .write_relationships(vec![
            // Role assignments
            relationship("role:readers", "member", "user:alice"),
            relationship("role:writers", "member", "user:bob"),
            relationship("role:writers", "member", "user:charlie"),
            relationship("role:admins", "member", "user:charlie"),
            relationship("role:admins", "member", "user:dave"),
            // Resource permissions
            relationship("resource:public", "reader_role", "role:readers"),
            relationship("resource:internal", "writer_role", "role:writers"),
            relationship("resource:confidential", "admin_role", "role:admins"),
        ])
        .await
        .unwrap();

    // Alice (reader) can only read public
    fixture.assert_allowed("user:alice", "resource:public", "can_read").await;
    fixture.assert_denied("user:alice", "resource:internal", "can_read").await;
    fixture.assert_denied("user:alice", "resource:confidential", "can_read").await;

    // Bob (writer) can read/write internal
    fixture.assert_denied("user:bob", "resource:public", "can_read").await;
    fixture.assert_allowed("user:bob", "resource:internal", "can_read").await;
    fixture.assert_allowed("user:bob", "resource:internal", "can_write").await;
    fixture.assert_denied("user:bob", "resource:confidential", "can_read").await;

    // Charlie (writer + admin) can access internal and confidential
    fixture.assert_allowed("user:charlie", "resource:internal", "can_read").await;
    fixture.assert_allowed("user:charlie", "resource:internal", "can_write").await;
    fixture.assert_allowed("user:charlie", "resource:confidential", "can_read").await;
    fixture.assert_allowed("user:charlie", "resource:confidential", "can_write").await;
    fixture.assert_allowed("user:charlie", "resource:confidential", "can_delete").await;

    // Dave (admin) has full access to confidential
    fixture.assert_allowed("user:dave", "resource:confidential", "can_read").await;
    fixture.assert_allowed("user:dave", "resource:confidential", "can_write").await;
    fixture.assert_allowed("user:dave", "resource:confidential", "can_delete").await;
}
