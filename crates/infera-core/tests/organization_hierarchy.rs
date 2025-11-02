//! Integration test: Organization hierarchy scenario
//!
//! This test implements a realistic organization structure with:
//! - Organizations with members
//! - Teams within organizations
//! - Projects owned by teams
//! - Hierarchical permissions flowing down

use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

mod common;
use common::{TestFixture, relationship};

/// Create an organization hierarchy schema
fn create_schema() -> Schema {
    Schema::new(vec![
        // Organization type
        TypeDef::new(
            "organization".to_string(),
            vec![
                RelationDef::new("admin".to_string(), None),
                RelationDef::new("member".to_string(), None),
                // can_manage = admin
                RelationDef::new(
                    "can_manage".to_string(),
                    Some(RelationExpr::RelationRef {
                        relation: "admin".to_string(),
                    }),
                ),
            ],
        ),
        // Team type
        TypeDef::new(
            "team".to_string(),
            vec![
                RelationDef::new("organization".to_string(), None), // parent org
                RelationDef::new("lead".to_string(), None),
                RelationDef::new("member".to_string(), None),
                // can_view = member | lead | organization->admin
                RelationDef::new(
                    "can_view".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef {
                            relation: "member".to_string(),
                        },
                        RelationExpr::RelationRef {
                            relation: "lead".to_string(),
                        },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "organization".to_string(),
                            computed: "admin".to_string(),
                        },
                    ])),
                ),
                // can_manage = lead | organization->admin
                RelationDef::new(
                    "can_manage".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelationRef {
                            relation: "lead".to_string(),
                        },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "organization".to_string(),
                            computed: "admin".to_string(),
                        },
                    ])),
                ),
            ],
        ),
        // Project type
        TypeDef::new(
            "project".to_string(),
            vec![
                RelationDef::new("team".to_string(), None), // owning team
                RelationDef::new("contributor".to_string(), None),
                // can_view = contributor | team->can_view
                RelationDef::new(
                    "can_view".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef {
                            relation: "contributor".to_string(),
                        },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "team".to_string(),
                            computed: "can_view".to_string(),
                        },
                    ])),
                ),
                // can_edit = team->member | team->lead
                RelationDef::new(
                    "can_edit".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelatedObjectUserset {
                            relationship: "team".to_string(),
                            computed: "member".to_string(),
                        },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "team".to_string(),
                            computed: "lead".to_string(),
                        },
                    ])),
                ),
            ],
        ),
    ])
}

#[tokio::test]
async fn test_organization_admin_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Alice is admin of org1
    fixture
        .write_relationships(vec![relationship(
            "organization:org1",
            "admin",
            "user:alice",
        )])
        .await
        .unwrap();

    // Alice can manage the organization
    fixture
        .assert_allowed("user:alice", "organization:org1", "can_manage")
        .await;

    // Bob cannot
    fixture
        .assert_denied("user:bob", "organization:org1", "can_manage")
        .await;
}

#[tokio::test]
async fn test_team_member_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Bob is a member of team1
    fixture
        .write_relationships(vec![relationship("team:team1", "member", "user:bob")])
        .await
        .unwrap();

    // Bob can view the team
    fixture
        .assert_allowed("user:bob", "team:team1", "can_view")
        .await;

    // But cannot manage it
    fixture
        .assert_denied("user:bob", "team:team1", "can_manage")
        .await;
}

#[tokio::test]
async fn test_team_lead_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Charlie is the lead of team1
    fixture
        .write_relationships(vec![relationship("team:team1", "lead", "user:charlie")])
        .await
        .unwrap();

    // Charlie can both view and manage the team
    fixture
        .assert_allowed("user:charlie", "team:team1", "can_view")
        .await;
    fixture
        .assert_allowed("user:charlie", "team:team1", "can_manage")
        .await;
}

#[tokio::test]
async fn test_hierarchical_org_to_team_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Set up hierarchy:
    // - Alice is admin of org1
    // - team1 belongs to org1
    fixture
        .write_relationships(vec![
            relationship("organization:org1", "admin", "user:alice"),
            relationship("team:team1", "organization", "organization:org1"),
        ])
        .await
        .unwrap();

    // Alice can view the team (through org admin)
    fixture
        .assert_allowed("user:alice", "team:team1", "can_view")
        .await;

    // Alice can manage the team (through org admin)
    fixture
        .assert_allowed("user:alice", "team:team1", "can_manage")
        .await;
}

#[tokio::test]
async fn test_project_team_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Set up:
    // - Bob is a member of team1
    // - project1 is owned by team1
    fixture
        .write_relationships(vec![
            relationship("team:team1", "member", "user:bob"),
            relationship("project:project1", "team", "team:team1"),
        ])
        .await
        .unwrap();

    // Bob can view the project (through team membership)
    fixture
        .assert_allowed("user:bob", "project:project1", "can_view")
        .await;

    // Bob can edit the project (team members can edit)
    fixture
        .assert_allowed("user:bob", "project:project1", "can_edit")
        .await;
}

#[tokio::test]
async fn test_full_hierarchy_org_to_project() {
    let fixture = TestFixture::new(create_schema());

    // Set up full hierarchy:
    // - Alice is admin of org1
    // - team1 belongs to org1
    // - project1 is owned by team1
    fixture
        .write_relationships(vec![
            relationship("organization:org1", "admin", "user:alice"),
            relationship("team:team1", "organization", "organization:org1"),
            relationship("project:project1", "team", "team:team1"),
        ])
        .await
        .unwrap();

    // Alice can view the project (org admin -> team viewer -> project viewer)
    fixture
        .assert_allowed("user:alice", "project:project1", "can_view")
        .await;

    // But Alice cannot edit the project (org admin doesn't grant team membership)
    // This is correct - admins can see everything but need to be team members to edit
    fixture
        .assert_denied("user:alice", "project:project1", "can_edit")
        .await;
}

#[tokio::test]
async fn test_multiple_teams_in_organization() {
    let fixture = TestFixture::new(create_schema());

    // Set up:
    // - org1 has alice as admin
    // - team1 and team2 belong to org1
    // - bob is member of team1
    // - charlie is member of team2
    fixture
        .write_relationships(vec![
            relationship("organization:org1", "admin", "user:alice"),
            relationship("team:team1", "organization", "organization:org1"),
            relationship("team:team2", "organization", "organization:org1"),
            relationship("team:team1", "member", "user:bob"),
            relationship("team:team2", "member", "user:charlie"),
        ])
        .await
        .unwrap();

    // Alice can view both teams (org admin)
    fixture
        .assert_allowed("user:alice", "team:team1", "can_view")
        .await;
    fixture
        .assert_allowed("user:alice", "team:team2", "can_view")
        .await;

    // Bob can only view team1
    fixture
        .assert_allowed("user:bob", "team:team1", "can_view")
        .await;
    fixture
        .assert_denied("user:bob", "team:team2", "can_view")
        .await;

    // Charlie can only view team2
    fixture
        .assert_denied("user:charlie", "team:team1", "can_view")
        .await;
    fixture
        .assert_allowed("user:charlie", "team:team2", "can_view")
        .await;
}

#[tokio::test]
async fn test_project_contributor_permissions() {
    let fixture = TestFixture::new(create_schema());

    // Dave is a contributor to project1 (not a team member)
    fixture
        .write_relationships(vec![relationship(
            "project:project1",
            "contributor",
            "user:dave",
        )])
        .await
        .unwrap();

    // Dave can view the project
    fixture
        .assert_allowed("user:dave", "project:project1", "can_view")
        .await;

    // But Dave cannot edit (only team members can edit)
    fixture
        .assert_denied("user:dave", "project:project1", "can_edit")
        .await;
}

#[tokio::test]
async fn test_complex_multi_level_hierarchy() {
    let fixture = TestFixture::new(create_schema());

    // Complex scenario:
    // - org1 with alice as admin
    // - team1 in org1 with bob as lead
    // - team2 in org1 with charlie as member
    // - project1 owned by team1
    // - project2 owned by team2
    // - dave is contributor to project2
    fixture
        .write_relationships(vec![
            relationship("organization:org1", "admin", "user:alice"),
            relationship("team:team1", "organization", "organization:org1"),
            relationship("team:team1", "lead", "user:bob"),
            relationship("team:team2", "organization", "organization:org1"),
            relationship("team:team2", "member", "user:charlie"),
            relationship("project:project1", "team", "team:team1"),
            relationship("project:project2", "team", "team:team2"),
            relationship("project:project2", "contributor", "user:dave"),
        ])
        .await
        .unwrap();

    // Alice (org admin) can view all teams and projects
    fixture
        .assert_allowed("user:alice", "team:team1", "can_view")
        .await;
    fixture
        .assert_allowed("user:alice", "team:team2", "can_view")
        .await;
    fixture
        .assert_allowed("user:alice", "project:project1", "can_view")
        .await;
    fixture
        .assert_allowed("user:alice", "project:project2", "can_view")
        .await;

    // Bob (team1 lead) can view and manage team1, and edit project1
    fixture
        .assert_allowed("user:bob", "team:team1", "can_view")
        .await;
    fixture
        .assert_allowed("user:bob", "team:team1", "can_manage")
        .await;
    fixture
        .assert_allowed("user:bob", "project:project1", "can_view")
        .await;
    fixture
        .assert_allowed("user:bob", "project:project1", "can_edit")
        .await;

    // Bob cannot access team2 or project2
    fixture
        .assert_denied("user:bob", "team:team2", "can_view")
        .await;
    fixture
        .assert_denied("user:bob", "project:project2", "can_view")
        .await;

    // Charlie (team2 member) can view team2 and edit project2
    fixture
        .assert_allowed("user:charlie", "team:team2", "can_view")
        .await;
    fixture
        .assert_allowed("user:charlie", "project:project2", "can_view")
        .await;
    fixture
        .assert_allowed("user:charlie", "project:project2", "can_edit")
        .await;

    // Dave (project2 contributor) can only view project2
    fixture
        .assert_allowed("user:dave", "project:project2", "can_view")
        .await;
    fixture
        .assert_denied("user:dave", "project:project2", "can_edit")
        .await;
}
