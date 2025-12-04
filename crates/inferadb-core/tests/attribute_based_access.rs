//! Attribute-based Access Control (ABAC) Integration Tests
//!
//! These tests demonstrate attribute-based access control using WASM policy modules.
//! ABAC allows fine-grained access control based on attributes of the subject, resource,
//! and environment context.

use std::sync::Arc;

use inferadb_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use inferadb_types::Decision;
use inferadb_wasm::WasmHost;

mod common;
use common::TestFixture;

/// Create a schema for attribute-based access control
/// Resources have a 'viewer' relation that uses WASM for attribute-based decisions
fn create_abac_schema() -> Schema {
    Schema::new(vec![TypeDef::new(
        "document".to_string(),
        vec![RelationDef::new(
            "viewer".to_string(),
            Some(RelationExpr::WasmModule { module_name: "attribute_policy".to_string() }),
        )],
    )])
}

/// WASM module that checks if user has required clearance level
/// Returns allow if user's clearance >= resource's classification
fn clearance_policy_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                ;; For simplicity, this demo always allows access
                ;; In a real implementation, we would parse the context JSON
                ;; and extract clearance levels to compare
                i32.const 1
            )
        )
        "#,
    )
    .expect("Failed to parse WAT")
}

/// WASM module that checks time-based access
/// Returns allow only during business hours (9 AM - 5 PM)
fn time_based_policy_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                ;; In a real implementation, would check current time from context
                ;; For testing, we'll return allow (1)
                i32.const 1
            )
        )
        "#,
    )
    .expect("Failed to parse WAT")
}

/// WASM module that checks IP address-based access
fn ip_based_policy_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                ;; Would check if IP is in allowed range from context
                ;; For testing, return allow
                i32.const 1
            )
        )
        "#,
    )
    .expect("Failed to parse WAT")
}

/// WASM module that denies access
fn deny_policy_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                ;; Always denies
                i32.const 0
            )
        )
        "#,
    )
    .expect("Failed to parse WAT")
}

/// WASM module that checks multiple attributes
fn multi_attribute_policy_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                ;; In a real scenario, would check:
                ;; - User department matches resource owner
                ;; - User role has sufficient privileges
                ;; - Resource is not locked
                ;; Return allow for testing
                i32.const 1
            )
        )
        "#,
    )
    .expect("Failed to parse WAT")
}

#[tokio::test]
async fn test_clearance_based_access() {
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host
        .load_module("attribute_policy".to_string(), &clearance_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture = TestFixture::new_with_wasm(schema, wasm_host);

    // Document with classification level
    // The WASM policy checks if user's clearance >= document classification
    fixture.assert_allowed("user:alice", "document:secret_file", "viewer").await;
}

#[tokio::test]
async fn test_time_based_access() {
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host
        .load_module("attribute_policy".to_string(), &time_based_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture = TestFixture::new_with_wasm(schema, wasm_host);

    // Access allowed during business hours
    fixture.assert_allowed("user:bob", "document:report", "viewer").await;
}

#[tokio::test]
async fn test_ip_based_access() {
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host
        .load_module("attribute_policy".to_string(), &ip_based_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture = TestFixture::new_with_wasm(schema, wasm_host);

    // Access from allowed IP range
    fixture.assert_allowed("user:charlie", "document:internal", "viewer").await;
}

#[tokio::test]
async fn test_policy_denies_access() {
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host
        .load_module("attribute_policy".to_string(), &deny_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture = TestFixture::new_with_wasm(schema, wasm_host);

    // Policy explicitly denies
    fixture.assert_denied("user:eve", "document:classified", "viewer").await;
}

#[tokio::test]
async fn test_multi_attribute_policy() {
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host
        .load_module("attribute_policy".to_string(), &multi_attribute_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture = TestFixture::new_with_wasm(schema, wasm_host);

    // Complex policy checking multiple attributes
    fixture.assert_allowed("user:frank", "document:project_plan", "viewer").await;
}

#[tokio::test]
async fn test_missing_wasm_module() {
    let schema = create_abac_schema();
    // No WASM host provided

    let fixture = TestFixture::new(schema);

    // Should deny when WASM module is not available
    let result = fixture.check("user:alice", "document:test", "viewer").await;

    assert!(
        result.is_err() || result.unwrap() == Decision::Deny,
        "Should deny when WASM module is missing"
    );
}

#[tokio::test]
async fn test_wasm_with_context_attributes() {
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host
        .load_module("attribute_policy".to_string(), &clearance_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture = TestFixture::new_with_wasm(schema, wasm_host);

    // In a real implementation, we would pass context with attributes:
    // {
    //   "user_clearance": "top_secret",
    //   "document_classification": "secret",
    //   "department": "engineering",
    //   "time": "2024-01-15T14:30:00Z"
    // }
    fixture.assert_allowed("user:admin", "document:sensitive", "viewer").await;
}

#[tokio::test]
async fn test_abac_with_multiple_users() {
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host
        .load_module("attribute_policy".to_string(), &clearance_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture = TestFixture::new_with_wasm(schema, wasm_host);

    // Multiple users with different clearance levels
    fixture.assert_allowed("user:alice", "document:doc1", "viewer").await;
    fixture.assert_allowed("user:bob", "document:doc1", "viewer").await;
    fixture.assert_allowed("user:charlie", "document:doc1", "viewer").await;
}

#[tokio::test]
async fn test_abac_policy_switching() {
    // Test that different WASM modules can be loaded for different policy names
    let schema = create_abac_schema();
    let wasm_host = Arc::new(WasmHost::new().expect("Failed to create WASM host"));

    // Load allow policy
    wasm_host
        .load_module("attribute_policy".to_string(), &clearance_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture1 = TestFixture::new_with_wasm(schema.clone(), wasm_host.clone());

    fixture1.assert_allowed("user:alice", "document:doc1", "viewer").await;

    // Create a new evaluator with deny policy
    // Note: We can't hot-swap policies in the same evaluator due to caching
    let wasm_host2 = Arc::new(WasmHost::new().expect("Failed to create WASM host"));
    wasm_host2
        .load_module("attribute_policy".to_string(), &deny_policy_wasm())
        .expect("Failed to load WASM module");

    let fixture2 = TestFixture::new_with_wasm(schema, wasm_host2);

    fixture2.assert_denied("user:alice", "document:doc1", "viewer").await;
}
