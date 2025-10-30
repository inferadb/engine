//! Integration tests for WASM policy modules

use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
use infera_core::{CheckRequest, Decision, Evaluator};
use infera_store::{MemoryBackend, Tuple, TupleStore};
use infera_wasm::WasmHost;
use std::sync::Arc;

/// Helper to create a simple schema with WASM module
fn create_wasm_schema(module_name: &str) -> Schema {
    Schema::new(vec![TypeDef::new(
        "document".to_string(),
        vec![RelationDef::new(
            "viewer".to_string(),
            Some(RelationExpr::WasmModule {
                module_name: module_name.to_string(),
            }),
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
                RelationExpr::WasmModule {
                    module_name: module_name.to_string(),
                },
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
                RelationExpr::WasmModule {
                    module_name: module_name.to_string(),
                },
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
    wasm_host
        .load_module("allow_all".to_string(), &wasm)
        .unwrap();

    let schema = create_wasm_schema("allow_all");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn TupleStore>,
        Arc::new(schema),
        Some(wasm_host),
    );

    // Test check - should allow due to WASM module
    let request = CheckRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
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
    wasm_host
        .load_module("deny_all".to_string(), &wasm)
        .unwrap();

    let schema = create_wasm_schema("deny_all");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn TupleStore>,
        Arc::new(schema),
        Some(wasm_host),
    );

    // Test check - should deny due to WASM module
    let request = CheckRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
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
    wasm_host
        .load_module("business_hours".to_string(), &wasm)
        .unwrap();

    let schema = create_union_schema("business_hours");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn TupleStore>,
        Arc::new(schema),
        Some(wasm_host),
    );

    // Add direct tuple
    store
        .write(vec![Tuple {
            object: "document:readme".to_string(),
            relation: "viewer".to_string(),
            user: "user:alice".to_string(),
        }])
        .await
        .unwrap();

    // Test check - should allow due to direct tuple (even though WASM denies)
    let request = CheckRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Allow);

    // Test with user not in direct tuples - should deny since WASM denies
    let request = CheckRequest {
        subject: "user:bob".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
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
    wasm_host
        .load_module("is_verified".to_string(), &wasm)
        .unwrap();

    let schema = create_intersection_schema("is_verified");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn TupleStore>,
        Arc::new(schema),
        Some(wasm_host),
    );

    // Add direct tuple
    store
        .write(vec![Tuple {
            object: "document:readme".to_string(),
            relation: "viewer".to_string(),
            user: "user:alice".to_string(),
        }])
        .await
        .unwrap();

    // Test check - should allow since both conditions met
    let request = CheckRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Allow);

    // Test with user not in direct tuples - should deny even though WASM allows
    let request = CheckRequest {
        subject: "user:bob".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
    };

    let decision = evaluator.check(request).await.unwrap();
    assert_eq!(decision, Decision::Deny);
}

#[tokio::test]
async fn test_wasm_missing_host() {
    let schema = create_wasm_schema("some_module");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn TupleStore>,
        Arc::new(schema),
        None, // No WASM host
    );

    // Test check - should error with WASM host not configured
    let request = CheckRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
    };

    let result = evaluator.check(request).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("WASM host not configured"));
}

#[tokio::test]
async fn test_wasm_module_not_loaded() {
    let wasm_host = Arc::new(WasmHost::new().unwrap());
    let schema = create_wasm_schema("nonexistent");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn TupleStore>,
        Arc::new(schema),
        Some(wasm_host),
    );

    // Test check - should error with module not found
    let request = CheckRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
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
    wasm_host
        .load_module("test_module".to_string(), &wasm)
        .unwrap();

    let schema = create_wasm_schema("test_module");
    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(
        store.clone() as Arc<dyn TupleStore>,
        Arc::new(schema),
        Some(wasm_host),
    );

    // Test check with trace
    let request = CheckRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
    };

    let trace = evaluator.check_with_trace(request).await.unwrap();
    assert_eq!(trace.decision, Decision::Allow);

    // Verify trace contains WASM node
    use infera_core::trace::NodeType;
    match &trace.root.node_type {
        NodeType::WasmModule { module_name } => {
            assert_eq!(module_name, "test_module");
        }
        _ => panic!("Expected WasmModule node type"),
    }
    assert!(trace.root.result);
}
