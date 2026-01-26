//! # Infera WASM - WebAssembly Policy Module Runtime
//!
//! Hosts sandboxed WASM policy modules with deterministic execution.

#![deny(unsafe_code)]

use std::{collections::HashMap, sync::RwLock};

use thiserror::Error;
use wasmtime::*;

pub mod host;
pub mod sandbox;

pub use host::{ExecutionContext, HostState, StoreLimits};
pub use sandbox::{Sandbox, SandboxConfig};

#[derive(Debug, Error)]
pub enum WasmError {
    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    #[error("Execution error: {0}")]
    Execution(String),

    #[error("Wasmtime error: {0}")]
    Wasmtime(#[from] wasmtime::Error),

    #[error("Invalid argument type")]
    InvalidArgumentType,

    #[error("Invalid sandbox configuration: {0}")]
    InvalidConfiguration(String),
}

pub type Result<T> = std::result::Result<T, WasmError>;

/// WASM module host
pub struct WasmHost {
    sandbox: Sandbox,
    modules: RwLock<HashMap<String, Module>>,
}

impl WasmHost {
    pub fn new() -> Result<Self> {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(config)?;

        Ok(Self { sandbox, modules: RwLock::new(HashMap::new()) })
    }

    pub fn new_with_config(config: SandboxConfig) -> Result<Self> {
        let sandbox = Sandbox::new(config)?;

        Ok(Self { sandbox, modules: RwLock::new(HashMap::new()) })
    }

    /// Load a WASM module
    pub fn load_module(&self, name: String, wasm_bytes: &[u8]) -> Result<()> {
        let module = Module::new(self.sandbox.engine(), wasm_bytes)?;

        let mut modules = self.modules.write().unwrap();
        modules.insert(name, module);

        Ok(())
    }

    /// Execute a function in a loaded module
    pub fn execute(
        &self,
        module_name: &str,
        func_name: &str,
        context: ExecutionContext,
    ) -> Result<bool> {
        let modules = self.modules.read().unwrap();
        let module = modules
            .get(module_name)
            .ok_or_else(|| WasmError::ModuleNotFound(module_name.to_string()))?;

        let result = self.sandbox.execute(module, func_name, context)?;

        // 0 = deny, non-zero = allow
        Ok(result != 0)
    }
}

/// Value types for WASM function calls
#[derive(Debug, Clone)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    String(String),
    Bool(bool),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_host_creation() {
        let host = WasmHost::new();
        assert!(host.is_ok());
    }

    #[test]
    fn test_wasm_host_with_config() {
        let config = SandboxConfig {
            max_execution_time: std::time::Duration::from_millis(50),
            store_limits: StoreLimits {
                max_memory_bytes: 5 * 1024 * 1024,
                max_table_elements: 500,
                max_instances: 1,
                max_tables: 1,
                max_memories: 1,
            },
            enable_wasi: false,
        };

        let host = WasmHost::new_with_config(config);
        assert!(host.is_ok());
    }

    #[test]
    fn test_load_simple_module() {
        let host = WasmHost::new().unwrap();

        // A simple WASM module that exports a function returning 1
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

        let result = host.load_module("simple".to_string(), &wasm);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_simple_module() {
        let host = WasmHost::new().unwrap();

        // Module that always returns 1 (allow)
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

        host.load_module("allow_all".to_string(), &wasm).unwrap();

        let context = ExecutionContext {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            context: None,
        };

        let result = host.execute("allow_all", "check", context);
        if result.is_err() {
            eprintln!("Error: {:?}", result.as_ref().err());
        }
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        assert!(result.unwrap());
    }

    #[test]
    fn test_execute_deny_module() {
        let host = WasmHost::new().unwrap();

        // Module that always returns 0 (deny)
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

        host.load_module("deny_all".to_string(), &wasm).unwrap();

        let context = ExecutionContext {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            context: None,
        };

        let result = host.execute("deny_all", "check", context);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_execute_nonexistent_module() {
        let host = WasmHost::new().unwrap();

        let context = ExecutionContext {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            context: None,
        };

        let result = host.execute("nonexistent", "check", context);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WasmError::ModuleNotFound(_)));
    }

    #[test]
    fn test_execute_nonexistent_function() {
        let host = WasmHost::new().unwrap();

        let wasm = wat::parse_str(
            r#"
            (module
                (func (export "other_function") (result i32)
                    i32.const 1
                )
            )
            "#,
        )
        .unwrap();

        host.load_module("test".to_string(), &wasm).unwrap();

        let context = ExecutionContext {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            context: None,
        };

        let result = host.execute("test", "check", context);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WasmError::FunctionNotFound(_)));
    }

    #[test]
    fn test_module_with_memory() {
        let host = WasmHost::new().unwrap();

        // Module with memory that returns 1
        let wasm = wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (func (export "check") (result i32)
                    i32.const 1
                )
            )
            "#,
        )
        .unwrap();

        host.load_module("with_memory".to_string(), &wasm).unwrap();

        let context = ExecutionContext {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            context: None,
        };

        let result = host.execute("with_memory", "check", context);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_module_with_log_host_function() {
        let host = WasmHost::new().unwrap();

        // Module that uses the log host function
        let wasm = wat::parse_str(
            r#"
            (module
                (import "host" "log" (func $log (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "test message")
                (func (export "check") (result i32)
                    i32.const 0
                    i32.const 12
                    call $log
                    i32.const 1
                )
            )
            "#,
        )
        .unwrap();

        host.load_module("with_log".to_string(), &wasm).unwrap();

        let context = ExecutionContext {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            context: None,
        };

        let result = host.execute("with_log", "check", context);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
