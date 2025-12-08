//! Sandboxed WASM execution with resource limits

use std::time::Duration;

use wasmtime::*;

use crate::{
    Result, WasmError,
    host::{ExecutionContext, HostFunctions, HostState, StoreLimits},
};

/// Configuration for WASM execution sandbox
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Memory limits
    pub store_limits: StoreLimits,
    /// Enable WASI
    pub enable_wasi: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_execution_time: Duration::from_millis(100),
            store_limits: StoreLimits::default(),
            enable_wasi: false,
        }
    }
}

/// A sandboxed WASM execution environment
pub struct Sandbox {
    engine: Engine,
    linker: Linker<HostState>,
    config: SandboxConfig,
}

impl Sandbox {
    /// Create a new sandbox with the given configuration
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let mut engine_config = Config::new();

        // Enable features needed for host functions
        engine_config.wasm_bulk_memory(true);
        engine_config.wasm_multi_memory(true);

        // Consume fuel for deterministic execution and limits
        engine_config.consume_fuel(true);

        let engine = Engine::new(&engine_config)?;
        let mut linker = Linker::new(&engine);

        // Add host functions
        HostFunctions::add_to_linker(&mut linker)?;

        Ok(Self { engine, linker, config })
    }

    /// Execute a WASM module in the sandbox
    pub fn execute(
        &self,
        module: &Module,
        function_name: &str,
        context: ExecutionContext,
    ) -> Result<i32> {
        let host_state = HostState::new(context);
        let mut store = Store::new(&self.engine, host_state);

        // Set resource limits
        store.limiter(|state| state);

        // Set fuel limit (roughly corresponds to instruction count)
        // 1 million instructions should be plenty for policy checks
        store
            .set_fuel(1_000_000)
            .map_err(|e| WasmError::Execution(format!("Failed to set fuel: {}", e)))?;

        // Instantiate the module
        let instance = self
            .linker
            .instantiate(&mut store, module)
            .map_err(|e| WasmError::Execution(format!("Failed to instantiate: {}", e)))?;

        // Get the function
        let func = instance
            .get_typed_func::<(), i32>(&mut store, function_name)
            .map_err(|e| WasmError::FunctionNotFound(format!("{}: {}", function_name, e)))?;

        // Execute the function
        let result = func.call(&mut store, ()).map_err(|e| {
            if e.to_string().contains("fuel") {
                WasmError::Execution("Instruction limit exceeded".to_string())
            } else {
                WasmError::Execution(format!("Execution failed: {}", e))
            }
        })?;

        Ok(result)
    }

    /// Get the engine
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the sandbox configuration
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_creation() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(config);
        assert!(sandbox.is_ok());
    }

    #[test]
    fn test_sandbox_with_custom_limits() {
        let config = SandboxConfig {
            max_execution_time: Duration::from_millis(50),
            store_limits: StoreLimits {
                max_memory_bytes: 5 * 1024 * 1024, // 5 MB
                ..Default::default()
            },
            ..Default::default()
        };

        let sandbox = Sandbox::new(config);
        assert!(sandbox.is_ok());
    }
}
