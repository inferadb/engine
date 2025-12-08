//! Integration tests for forbid policies
//!
//! Tests that forbid rules correctly override permit rules with explicit deny semantics.

use inferadb_engine_core::ipl::parse_schema;

mod common;
use common::{TestFixture, relationship};

#[tokio::test]
async fn test_forbid_overrides_permit() {
    // Schema: viewers can access, but blocked users are forbidden
    let schema_text = r#"
        type document {
            relation viewer
            forbid blocked
        }
    "#;

    let schema = parse_schema(schema_text).unwrap();
    let fixture = TestFixture::new(schema);

    // Alice is a viewer and also blocked
    fixture
        .write_relationships(vec![
            relationship("document:readme", "viewer", "user:alice"),
            relationship("document:readme", "blocked", "user:alice"),
        ])
        .await
        .unwrap();

    // Check: Alice is viewer but blocked, so access should be DENIED
    fixture.assert_denied("user:alice", "document:readme", "viewer").await;
}

#[tokio::test]
async fn test_forbid_without_permit() {
    // Schema: users can be blocked even without any permit
    let schema_text = r#"
        type document {
            relation viewer
            forbid blocked
        }
    "#;

    let schema = parse_schema(schema_text).unwrap();
    let fixture = TestFixture::new(schema);

    // Bob is blocked but not a viewer
    fixture
        .write_relationships(vec![relationship("document:readme", "blocked", "user:bob")])
        .await
        .unwrap();

    // Check: Bob is blocked (no permit anyway)
    fixture.assert_denied("user:bob", "document:readme", "viewer").await;
}

#[tokio::test]
async fn test_permit_without_forbid() {
    // Schema: viewers can access, blocked users cannot
    let schema_text = r#"
        type document {
            relation viewer
            forbid blocked
        }
    "#;

    let schema = parse_schema(schema_text).unwrap();
    let fixture = TestFixture::new(schema);

    // Charlie is a viewer and NOT blocked
    fixture
        .write_relationships(vec![relationship("document:readme", "viewer", "user:charlie")])
        .await
        .unwrap();

    // Check: Charlie can access (viewer, not blocked)
    fixture.assert_allowed("user:charlie", "document:readme", "viewer").await;
}

#[tokio::test]
async fn test_forbid_with_union_expression() {
    // Schema: blocked or suspended users are forbidden
    let schema_text = r#"
        type document {
            relation viewer
            relation blocked_user
            relation suspended_user
            forbid denied: blocked_user | suspended_user
        }
    "#;

    let schema = parse_schema(schema_text).unwrap();
    let fixture = TestFixture::new(schema);

    // Alice is viewer and blocked
    fixture
        .write_relationships(vec![
            relationship("document:readme", "viewer", "user:alice"),
            relationship("document:readme", "blocked_user", "user:alice"),
        ])
        .await
        .unwrap();

    // Bob is viewer and suspended
    fixture
        .write_relationships(vec![
            relationship("document:readme", "viewer", "user:bob"),
            relationship("document:readme", "suspended_user", "user:bob"),
        ])
        .await
        .unwrap();

    // Check Alice: blocked via union
    fixture.assert_denied("user:alice", "document:readme", "viewer").await;

    // Check Bob: suspended via union
    fixture.assert_denied("user:bob", "document:readme", "viewer").await;
}

#[tokio::test]
async fn test_multiple_forbids_order_independent() {
    // Schema: multiple forbid rules, any match denies
    let schema_text = r#"
        type document {
            relation viewer
            forbid blocked
            forbid suspended
        }
    "#;

    let schema = parse_schema(schema_text).unwrap();
    let fixture = TestFixture::new(schema);

    // Alice is viewer and blocked
    fixture
        .write_relationships(vec![
            relationship("document:readme", "viewer", "user:alice"),
            relationship("document:readme", "blocked", "user:alice"),
        ])
        .await
        .unwrap();

    // Bob is viewer and suspended
    fixture
        .write_relationships(vec![
            relationship("document:readme", "viewer", "user:bob"),
            relationship("document:readme", "suspended", "user:bob"),
        ])
        .await
        .unwrap();

    // Both should be denied
    fixture.assert_denied("user:alice", "document:readme", "viewer").await;

    fixture.assert_denied("user:bob", "document:readme", "viewer").await;
}

#[tokio::test]
async fn test_forbid_vs_exclusion() {
    // Schema: Demonstrate difference between forbid and exclusion
    // Exclusion: editor - blocked means "editors who are not blocked"
    // Forbid: blocked forbids access regardless of editor status
    let schema_text = r#"
        type document {
            relation editor
            relation blocked_user
            relation viewer: editor - blocked_user
            forbid blocked: blocked_user
        }
    "#;

    let schema = parse_schema(schema_text).unwrap();
    let fixture = TestFixture::new(schema);

    // Alice is editor and blocked
    fixture
        .write_relationships(vec![
            relationship("document:readme", "editor", "user:alice"),
            relationship("document:readme", "blocked_user", "user:alice"),
        ])
        .await
        .unwrap();

    // Check viewer permission: exclusion means alice is NOT a viewer
    fixture.assert_denied("user:alice", "document:readme", "viewer").await;

    // Check editor permission: forbid blocks even direct editor access
    fixture.assert_denied("user:alice", "document:readme", "editor").await;
}

#[tokio::test]
async fn test_forbid_with_trace() {
    // Test that forbid shows up correctly in trace
    let schema_text = r#"
        type document {
            relation viewer
            forbid blocked
        }
    "#;

    let schema = parse_schema(schema_text).unwrap();
    let fixture = TestFixture::new(schema);

    // Alice is viewer and blocked
    fixture
        .write_relationships(vec![
            relationship("document:readme", "viewer", "user:alice"),
            relationship("document:readme", "blocked", "user:alice"),
        ])
        .await
        .unwrap();

    // Check with trace
    let request = inferadb_engine_types::EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: Some(true),
    };

    let trace = fixture.evaluator.check_with_trace(request).await.unwrap();
    assert_eq!(trace.decision, inferadb_engine_types::Decision::Deny, "Trace should show deny");
    assert!(trace.root.result, "Forbid node should be true (matched)");
}
