//! Host functions available to WASM modules

use wasmtime::*;
use serde::{Deserialize, Serialize};

/// Context passed to WASM modules during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Subject making the request
    pub subject: String,
    /// Resource being accessed
    pub resource: String,
    /// Permission being checked
    pub permission: String,
    /// Additional context data
    pub context: Option<serde_json::Value>,
}

/// Host functions that WASM modules can call
pub struct HostFunctions;

impl HostFunctions {
    /// Add all host functions to the linker
    pub fn add_to_linker(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
        // Log function - allows WASM to log messages
        linker.func_wrap(
            "host",
            "log",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                if let Some(mem) = caller.get_export("memory") {
                    if let Some(memory) = mem.into_memory() {
                        let data = memory.data(&caller);

                        if ptr >= 0 && len >= 0 && (ptr as usize + len as usize) <= data.len() {
                            let message_bytes = &data[ptr as usize..(ptr as usize + len as usize)];
                            if let Ok(message) = std::str::from_utf8(message_bytes) {
                                let message_string = message.to_string();
                                tracing::debug!(target: "wasm", "WASM log: {}", message_string);
                                drop(data); // Drop the immutable borrow
                                caller.data_mut().logs.push(message_string);
                            }
                        }
                    }
                }
            },
        )?;

        Ok(())
    }
}

/// State maintained during WASM execution
pub struct HostState {
    pub context: ExecutionContext,
    pub logs: Vec<String>,
    pub store_limits: StoreLimits,
}

impl HostState {
    pub fn new(context: ExecutionContext) -> Self {
        Self {
            context,
            logs: Vec::new(),
            store_limits: StoreLimits::default(),
        }
    }
}

/// Limits for WASM execution
#[derive(Debug, Clone)]
pub struct StoreLimits {
    pub max_memory_bytes: usize,
    pub max_table_elements: u32,
    pub max_instances: usize,
    pub max_tables: usize,
    pub max_memories: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 10 * 1024 * 1024, // 10 MB
            max_table_elements: 1000,
            max_instances: 1,
            max_tables: 1,
            max_memories: 1,
        }
    }
}

impl ResourceLimiter for HostState {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> anyhow::Result<bool> {
        Ok(desired <= self.store_limits.max_memory_bytes)
    }

    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> anyhow::Result<bool> {
        Ok(desired as u32 <= self.store_limits.max_table_elements)
    }
}
