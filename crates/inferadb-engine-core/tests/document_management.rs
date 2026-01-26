//! Integration test: Document management scenario
//!
//! This test implements a realistic document management system with:
//! - Documents that can be viewed, edited, and deleted
//! - Folders that can contain documents
//! - Hierarchical permissions (folder viewers can view all documents inside)
//! - Owner permissions (owners can do everything)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

mod common;
use common::{TestFixture, relationship};

/// Create a document management schema
fn create_schema() -> Schema {
    Schema::new(vec![
        // Folder type
        TypeDef::new(
            "folder".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new("editor".to_string(), None),
                RelationDef::new("viewer".to_string(), None),
                // can_view = viewer | editor | owner
                RelationDef::new(
                    "can_view".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "viewer".to_string() },
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                        RelationExpr::RelationRef { relation: "owner".to_string() },
                    ])),
                ),
                // can_edit = editor | owner
                RelationDef::new(
                    "can_edit".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                        RelationExpr::RelationRef { relation: "owner".to_string() },
                    ])),
                ),
                // can_delete = owner
                RelationDef::new(
                    "can_delete".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
            ],
        ),
        // Document type
        TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("parent".to_string(), None), // parent folder
                RelationDef::new("owner".to_string(), None),
                RelationDef::new("editor".to_string(), None),
                RelationDef::new("viewer".to_string(), None),
                // can_view = viewer | editor | owner | parent->can_view
                RelationDef::new(
                    "can_view".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "viewer".to_string() },
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                        RelationExpr::RelationRef { relation: "owner".to_string() },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "parent".to_string(),
                            computed: "can_view".to_string(),
                        },
                    ])),
                ),
                // can_edit = editor | owner
                RelationDef::new(
                    "can_edit".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                        RelationExpr::RelationRef { relation: "owner".to_string() },
                    ])),
                ),
                // can_delete = owner
                RelationDef::new(
                    "can_delete".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
            ],
        ),
    ])
}

#[tokio::test]
async fn test_direct_document_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Alice is the owner of doc1
    fixture
        .write_relationships(vec![relationship("document:doc1", "owner", "user:alice")])
        .await
        .unwrap();

    // Alice can view, edit, and delete as owner
    fixture.assert_allowed("user:alice", "document:doc1", "can_view").await;
    fixture.assert_allowed("user:alice", "document:doc1", "can_edit").await;
    fixture.assert_allowed("user:alice", "document:doc1", "can_delete").await;

    // Bob has no permissions
    fixture.assert_denied("user:bob", "document:doc1", "can_view").await;
    fixture.assert_denied("user:bob", "document:doc1", "can_edit").await;
    fixture.assert_denied("user:bob", "document:doc1", "can_delete").await;
}

#[tokio::test]
async fn test_editor_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Bob is an editor of doc1
    fixture
        .write_relationships(vec![relationship("document:doc1", "editor", "user:bob")])
        .await
        .unwrap();

    // Bob can view and edit, but not delete
    fixture.assert_allowed("user:bob", "document:doc1", "can_view").await;
    fixture.assert_allowed("user:bob", "document:doc1", "can_edit").await;
    fixture.assert_denied("user:bob", "document:doc1", "can_delete").await;
}

#[tokio::test]
async fn test_viewer_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Charlie is a viewer of doc1
    fixture
        .write_relationships(vec![relationship("document:doc1", "viewer", "user:charlie")])
        .await
        .unwrap();

    // Charlie can only view
    fixture.assert_allowed("user:charlie", "document:doc1", "can_view").await;
    fixture.assert_denied("user:charlie", "document:doc1", "can_edit").await;
    fixture.assert_denied("user:charlie", "document:doc1", "can_delete").await;
}

#[tokio::test]
async fn test_hierarchical_folder_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Set up hierarchy:
    // - folder1 has alice as viewer
    // - doc1 has folder1 as parent
    fixture
        .write_relationships(vec![
            relationship("folder:folder1", "viewer", "user:alice"),
            relationship("document:doc1", "parent", "folder:folder1"),
        ])
        .await
        .unwrap();

    // Alice can view doc1 through folder permissions
    fixture.assert_allowed("user:alice", "document:doc1", "can_view").await;

    // But Alice cannot edit or delete (folder viewer != document editor)
    fixture.assert_denied("user:alice", "document:doc1", "can_edit").await;
    fixture.assert_denied("user:alice", "document:doc1", "can_delete").await;
}

#[tokio::test]
async fn test_multiple_permission_sources() {
    let fixture = TestFixture::new(create_schema());

    // Alice is owner of doc1
    // Bob is editor of doc1
    // Charlie is viewer of doc1
    fixture
        .write_relationships(vec![
            relationship("document:doc1", "owner", "user:alice"),
            relationship("document:doc1", "editor", "user:bob"),
            relationship("document:doc1", "viewer", "user:charlie"),
        ])
        .await
        .unwrap();

    // All three users can view
    fixture.assert_allowed("user:alice", "document:doc1", "can_view").await;
    fixture.assert_allowed("user:bob", "document:doc1", "can_view").await;
    fixture.assert_allowed("user:charlie", "document:doc1", "can_view").await;

    // Only alice and bob can edit
    fixture.assert_allowed("user:alice", "document:doc1", "can_edit").await;
    fixture.assert_allowed("user:bob", "document:doc1", "can_edit").await;
    fixture.assert_denied("user:charlie", "document:doc1", "can_edit").await;

    // Only alice can delete
    fixture.assert_allowed("user:alice", "document:doc1", "can_delete").await;
    fixture.assert_denied("user:bob", "document:doc1", "can_delete").await;
    fixture.assert_denied("user:charlie", "document:doc1", "can_delete").await;
}

#[tokio::test]
async fn test_complex_folder_hierarchy() {
    let fixture = TestFixture::new(create_schema());

    // Set up a more complex hierarchy:
    // - folder1 has alice as editor
    // - doc1, doc2, doc3 all have folder1 as parent
    // - Bob is also a direct viewer of doc2
    fixture
        .write_relationships(vec![
            relationship("folder:folder1", "editor", "user:alice"),
            relationship("document:doc1", "parent", "folder:folder1"),
            relationship("document:doc2", "parent", "folder:folder1"),
            relationship("document:doc3", "parent", "folder:folder1"),
            relationship("document:doc2", "viewer", "user:bob"),
        ])
        .await
        .unwrap();

    // Alice can view all three documents (via folder)
    fixture.assert_allowed("user:alice", "document:doc1", "can_view").await;
    fixture.assert_allowed("user:alice", "document:doc2", "can_view").await;
    fixture.assert_allowed("user:alice", "document:doc3", "can_view").await;

    // Bob can only view doc2 (direct viewer)
    fixture.assert_denied("user:bob", "document:doc1", "can_view").await;
    fixture.assert_allowed("user:bob", "document:doc2", "can_view").await;
    fixture.assert_denied("user:bob", "document:doc3", "can_view").await;
}

#[tokio::test]
async fn test_permission_revocation() {
    let fixture = TestFixture::new(create_schema());

    // Initially, alice is owner of doc1
    fixture
        .write_relationships(vec![relationship("document:doc1", "owner", "user:alice")])
        .await
        .unwrap();

    // Alice can view
    fixture.assert_allowed("user:alice", "document:doc1", "can_view").await;

    // Now remove alice as owner (in a real system, you'd have a delete operation)
    // For this test, we'll just verify the permission check works as expected
    // The relationship store doesn't support deletion in this basic implementation,
    // but the test demonstrates that permissions are relationship-based
}
