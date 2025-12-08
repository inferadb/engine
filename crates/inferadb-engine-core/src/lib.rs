//! # Infera Core - Policy Evaluation Engine
//!
//! Core reasoning and policy evaluation engine for InferaDB.
//! Handles IPL parsing, relationship graph traversal, and decision evaluation.

use thiserror::Error;

pub mod evaluator;
pub mod graph;
pub mod ipl;
pub mod optimizer;
pub mod parallel;
pub mod trace;

pub use evaluator::Evaluator;
pub use trace::{DecisionTrace, EvaluationNode, NodeType};

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("Store error: {0}")]
    Store(#[from] inferadb_engine_types::StoreError),

    #[error("WASM error: {0}")]
    Wasm(#[from] inferadb_engine_wasm::WasmError),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Evaluation error: {0}")]
    Evaluation(String),

    #[error("Permission denied")]
    PermissionDenied,
}

pub type Result<T> = std::result::Result<T, EvalError>;

#[cfg(test)]
mod tests {
    #[test]
    fn test_core_module() {
        // Core module exports are tested via integration tests
        // This placeholder ensures the test module compiles
    }
}
