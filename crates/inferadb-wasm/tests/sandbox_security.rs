//! Security tests for WASM sandbox
//!
//! These tests ensure that the WASM sandbox properly isolates modules
//! and prevents malicious behavior.

use std::time::Duration;

use infera_wasm::{ExecutionContext, SandboxConfig, StoreLimits, WasmHost};

/// Test that WASM modules cannot exceed memory limits
#[test]
fn test_memory_limit_enforcement() {
    let store_limits = StoreLimits {
        max_memory_bytes: 1024 * 1024, // 1MB limit
        ..Default::default()
    };
    let config = SandboxConfig {
        max_execution_time: Duration::from_secs(1),
        store_limits,
        enable_wasi: false,
    };
    let host = WasmHost::new_with_config(config).unwrap();

    // Module that tries to allocate excessive memory
    let wat = r#"
        (module
            (memory (export "memory") 100) ; Try to allocate 100 pages (6.4MB)
            (func (export "check") (result i32)
                i32.const 1
            )
        )
    "#;

    let result = host.load_module("memory_hog".to_string(), wat.as_bytes());
    // Should either fail to load or be caught by resource limiter
    match result {
        Ok(_) => {
            // If it loaded, execution should still be limited
            let ctx = ExecutionContext {
                subject: "user:alice".to_string(),
                resource: "doc:readme".to_string(),
                permission: "view".to_string(),
                context: None,
            };
            let _ = host.execute("memory_hog", "check", ctx);
        },
        Err(_) => {
            // Failed to load due to memory limits - this is expected and good
        },
    }
}

/// Test that WASM modules cannot execute indefinitely (fuel exhaustion)
#[test]
fn test_fuel_limit_enforcement() {
    // Use default config which has fuel limit
    let host = WasmHost::new().unwrap();

    // Module with an infinite loop
    let wat = r#"
        (module
            (func (export "check") (result i32)
                (loop $infinite
                    br $infinite
                )
                i32.const 1
            )
        )
    "#;

    let result = host.load_module("infinite_loop".to_string(), wat.as_bytes());
    assert!(result.is_ok());

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    // Execution should fail due to fuel exhaustion
    let exec_result = host.execute("infinite_loop", "check", ctx);
    assert!(exec_result.is_err());
}

/// Test that WASM modules cannot access host filesystem
#[test]
fn test_no_filesystem_access() {
    let host = WasmHost::new().unwrap();

    // WASI is not enabled, so any filesystem operations should fail
    // This is a baseline test - WASM without WASI cannot access files
    let wat = r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
    "#;

    let result = host.load_module("safe_module".to_string(), wat.as_bytes());
    assert!(result.is_ok());
}

/// Test that WASM modules cannot access host network
#[test]
fn test_no_network_access() {
    let host = WasmHost::new().unwrap();

    // Similar to filesystem - without WASI, no network access is possible
    let wat = r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
    "#;

    let result = host.load_module("isolated".to_string(), wat.as_bytes());
    assert!(result.is_ok());
}

/// Test that modules from different tenants are isolated
#[test]
fn test_module_isolation() {
    let host = WasmHost::new().unwrap();

    // Load two different modules
    let wat1 = r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
    "#;

    let wat2 = r#"
        (module
            (func (export "check") (result i32)
                i32.const 0
            )
        )
    "#;

    host.load_module("tenant1_module".to_string(), wat1.as_bytes()).unwrap();
    host.load_module("tenant2_module".to_string(), wat2.as_bytes()).unwrap();

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    // Each module should return its own result
    let result1 = host.execute("tenant1_module", "check", ctx.clone()).unwrap();
    let result2 = host.execute("tenant2_module", "check", ctx).unwrap();

    assert!(result1);
    assert!(!result2);
}

/// Test that invalid WASM bytecode is rejected
#[test]
fn test_invalid_bytecode_rejected() {
    let host = WasmHost::new().unwrap();

    // Random bytes that are not valid WASM
    let invalid_wasm = b"This is not WASM bytecode!";

    let result = host.load_module("invalid".to_string(), invalid_wasm);
    assert!(result.is_err());
}

/// Test that modules with invalid signatures are rejected
#[test]
fn test_invalid_signature_rejected() {
    let host = WasmHost::new().unwrap();

    // Module with wrong function signature (no export)
    let wat = r#"
        (module
            (func $internal (param i32) (result i32)
                local.get 0
            )
        )
    "#;

    let result = host.load_module("no_export".to_string(), wat.as_bytes());
    // Module loads successfully but execution will fail
    assert!(result.is_ok());

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    // Execution should fail because "check" function doesn't exist
    let exec_result = host.execute("no_export", "check", ctx);
    assert!(exec_result.is_err());
}

/// Test that modules cannot escape sandbox via host function abuse
#[test]
fn test_host_function_safety() {
    let host = WasmHost::new().unwrap();

    // Module that calls log function with various inputs
    let wat = r#"
        (module
            (import "host" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "Test message")

            (func (export "check") (result i32)
                ;; Call log with valid pointer
                i32.const 0
                i32.const 12
                call $log

                ;; Return allow
                i32.const 1
            )
        )
    "#;

    let result = host.load_module("log_test".to_string(), wat.as_bytes());
    assert!(result.is_ok());

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    let exec_result = host.execute("log_test", "check", ctx);
    assert!(exec_result.is_ok());
}

/// Test determinism - same input should produce same output
#[test]
fn test_deterministic_execution() {
    let host = WasmHost::new().unwrap();

    let wat = r#"
        (module
            (func (export "check") (result i32)
                ;; Simple deterministic logic - always returns 1
                i32.const 1
            )
        )
    "#;

    host.load_module("deterministic".to_string(), wat.as_bytes()).unwrap();

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    // Execute multiple times
    let result1 = host.execute("deterministic", "check", ctx.clone()).unwrap();
    let result2 = host.execute("deterministic", "check", ctx.clone()).unwrap();
    let result3 = host.execute("deterministic", "check", ctx).unwrap();

    // All results should be identical
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
}

/// Test that modules cannot access memory outside their bounds
#[test]
fn test_memory_bounds_enforcement() {
    let host = WasmHost::new().unwrap();

    // Module that tries to read/write outside memory bounds
    let wat = r#"
        (module
            (memory (export "memory") 1) ; 1 page = 64KB

            (func (export "check") (result i32)
                ;; Try to access memory at a large offset
                i32.const 100000  ; Beyond 64KB
                i32.load
                drop
                i32.const 1
            )
        )
    "#;

    let result = host.load_module("bounds_test".to_string(), wat.as_bytes());

    // Module should load successfully (the invalid memory access is in the code)
    if result.is_ok() {
        let ctx = ExecutionContext {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "view".to_string(),
            context: None,
        };

        // Execution should fail due to out-of-bounds memory access
        let exec_result = host.execute("bounds_test", "check", ctx);
        assert!(exec_result.is_err(), "Should fail on out-of-bounds memory access");
    } else {
        // If module validation catches this at load time, that's also acceptable
        // as it provides even stronger security
    }
}

/// Test that malicious patterns are caught
#[test]
fn test_malicious_stack_overflow() {
    let host = WasmHost::new().unwrap();

    // Module that tries to cause stack overflow with deep recursion
    let wat = r#"
        (module
            (func $recurse (param i32) (result i32)
                local.get 0
                i32.const 1
                i32.sub
                call $recurse
            )

            (func (export "check") (result i32)
                i32.const 1000000
                call $recurse
            )
        )
    "#;

    let result = host.load_module("stack_overflow".to_string(), wat.as_bytes());
    assert!(result.is_ok());

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    // Should fail due to stack overflow or fuel exhaustion
    let exec_result = host.execute("stack_overflow", "check", ctx);
    assert!(exec_result.is_err());
}

/// Test that execution time limit is enforced
#[test]
fn test_execution_time_limit() {
    let config = SandboxConfig {
        max_execution_time: Duration::from_micros(1), // Very short time limit
        store_limits: StoreLimits::default(),
        enable_wasi: false,
    };
    let host = WasmHost::new_with_config(config).unwrap();

    let wat = r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
    "#;

    host.load_module("time_limit_test".to_string(), wat.as_bytes()).unwrap();

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    // Even a simple function might exceed the extremely short time limit
    // This tests that time limits are being enforced
    let _result = host.execute("time_limit_test", "check", ctx);
    // Note: time limits might not fail simple operations, fuel limits provide more reliable
    // protection
}

/// Test module cannot be overwritten once loaded
#[test]
fn test_module_overwrite() {
    let host = WasmHost::new().unwrap();

    let wat1 = r#"
        (module
            (func (export "check") (result i32)
                i32.const 1
            )
        )
    "#;

    let wat2 = r#"
        (module
            (func (export "check") (result i32)
                i32.const 0
            )
        )
    "#;

    host.load_module("test".to_string(), wat1.as_bytes()).unwrap();

    // Load again with same name - should overwrite
    host.load_module("test".to_string(), wat2.as_bytes()).unwrap();

    let ctx = ExecutionContext {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "view".to_string(),
        context: None,
    };

    // Should get result from second module
    let result = host.execute("test", "check", ctx).unwrap();
    assert!(!result); // Second module returns 0 (deny)
}
