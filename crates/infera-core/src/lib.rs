//! # Infera Core - Policy Evaluation Engine
//!
//! Core reasoning and policy evaluation engine for InferaDB.
//! Handles IPL parsing, relationship graph traversal, and decision evaluation.

use thiserror::Error;

pub mod evaluator;
pub mod graph;
pub mod ipl;
pub mod trace;
pub mod types;

pub use evaluator::Evaluator;
pub use types::*;
pub use trace::{DecisionTrace, EvaluationNode, NodeType};

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("Store error: {0}")]
    Store(#[from] infera_store::StoreError),

    #[error("WASM error: {0}")]
    Wasm(#[from] infera_wasm::WasmError),

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
        // Placeholder test
        assert!(true);
    }
}
