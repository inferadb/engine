//! Integration tests for WASM policy modules

use std::sync::Arc;

use inferadb_engine_core::{
    Evaluator,
    ipl::{RelationDef, RelationExpr, Schema, TypeDef},
};
use inferadb_engine_store::{MemoryBackend, RelationshipStore};
use inferadb_engine_types::{Decision, EvaluateRequest, Relationship};
use inferadb_engine_wasm::WasmHost;

/// Helper to create a simple schema with WASM module
fn create_wasm_schema(module_name: &str) -> Schema {
    Schema::new(vec![TypeDef::new(
        "document".to_string(),
        vec![RelationDef::new(
            "viewer".to_string(),
            Some(RelationExpr::WasmModule { module_name: module_name.to_string() }),
        )],
    )])
}

/// Helper to create a schema with union
fn create_union_schema(module_name: &str) -> Schema {
    Schema::new(vec![TypeDef::new(
        "document".to_string(),
        vec![RelationDef::new(
            "viewer".to_string(),
            Some(RelationExpr::Union(vec![
                RelationExpr::This,
                RelationExpr::WasmModule { module_name: module_name.to_string() },
            ])),
        )],
    )])
}

/// Helper to create a schema with intersection
fn create_intersection_schema(module_name: &str) -> Schema {
    Schema::new(vec![TypeDef::new(
        "document".to_string(),
        vec![RelationDef::new(
            "viewer".to_string(),
            Some(RelationExpr::Intersection(vec![
                RelationExpr::This,
                RelationExpr::WasmModule { module_name: module_name.to_string() },
            ])),
        )],
    )])
}

#[tokio::test]
async fn test_wasm_allow_policy() {
    // Create WASM module that always allows
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
        "#,
    )
    .unwrap();

    let wasm_host = Arc::new(WasmHost::new().unwrap());
    wasm_host.load_module("allow_all".to_string(), &wasm).unwrap();

    let schema = create_wasm_schema("allow_all");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema),
        Some(wasm_host),
        0i64,
    );

    // Test check - should allow due to WASM module
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Allow);
}

#[tokio::test]
async fn test_wasm_deny_policy() {
    // Create WASM module that always denies
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                i32.const 0
            )
        )
        "#,
    )
    .unwrap();

    let wasm_host = Arc::new(WasmHost::new().unwrap());
    wasm_host.load_module("deny_all".to_string(), &wasm).unwrap();

    let schema = create_wasm_schema("deny_all");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema),
        Some(wasm_host),
        0i64,
    );

    // Test check - should deny due to WASM module
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Deny);
}

#[tokio::test]
async fn test_wasm_with_union() {
    // Create WASM module that denies
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                i32.const 0
            )
        )
        "#,
    )
    .unwrap();

    let wasm_host = Arc::new(WasmHost::new().unwrap());
    wasm_host.load_module("business_hours".to_string(), &wasm).unwrap();

    let schema = create_union_schema("business_hours");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema),
        Some(wasm_host),
        0i64,
    );

    // Add direct relationship
    store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .unwrap();

    // Test check - should allow due to direct relationship (even though WASM denies)
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Allow);

    // Test with user not in direct relationships - should deny since WASM denies
    let request = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Deny);
}

#[tokio::test]
async fn test_wasm_with_intersection() {
    // Create WASM module that allows
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
        "#,
    )
    .unwrap();

    let wasm_host = Arc::new(WasmHost::new().unwrap());
    wasm_host.load_module("is_verified".to_string(), &wasm).unwrap();

    let schema = create_intersection_schema("is_verified");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema),
        Some(wasm_host),
        0i64,
    );

    // Add direct relationship
    store
        .write(
            0i64,
            vec![Relationship {
                resource: "document:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            }],
        )
        .await
        .unwrap();

    // Test check - should allow since both conditions met
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Allow);

    // Test with user not in direct relationships - should deny even though WASM allows
    let request = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Deny);
}

#[tokio::test]
async fn test_wasm_missing_host() {
    let schema = create_wasm_schema("some_module");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema),
        None, // No WASM host
        0i64,
    );

    // Test check - should error with WASM host not configured
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("WASM host not configured"));
}

#[tokio::test]
async fn test_wasm_module_not_loaded() {
    let wasm_host = Arc::new(WasmHost::new().unwrap());
    let schema = create_wasm_schema("nonexistent");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema),
        Some(wasm_host),
        0i64,
    );

    // Test check - should error with module not found
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Module not found"));
}

#[tokio::test]
async fn test_wasm_with_trace() {
    // Create WASM module that allows
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
        "#,
    )
    .unwrap();

    let wasm_host = Arc::new(WasmHost::new().unwrap());
    wasm_host.load_module("test_module".to_string(), &wasm).unwrap();

    let schema = create_wasm_schema("test_module");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn RelationshipStore>,
        Arc::new(schema),
        Some(wasm_host),
        0i64,
    );

    // Test check with trace
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let trace = evaluator.check_with_trace(request).await.unwrap();
    assert_eq!(trace.decision, Decision::Allow);

    // Verify trace contains WASM node
    use inferadb_engine_core::trace::NodeType;
    match &trace.root.node_type {
        NodeType::WasmModule { module_name } => {
            assert_eq!(module_name, "test_module");
        },
        _ => panic!("Expected WasmModule node type"),
    }
    assert!(trace.root.result);
}
