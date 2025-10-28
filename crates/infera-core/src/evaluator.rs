//! Policy evaluation engine

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{instrument, debug};

use crate::{CheckRequest, Decision, ExpandRequest, UsersetTree, Result, EvalError};
use infera_store::TupleStore;
use infera_wasm::WasmHost;

/// The main policy evaluator
pub struct Evaluator {
    store: Arc<dyn TupleStore>,
    wasm_host: Option<Arc<WasmHost>>,
}

impl Evaluator {
    pub fn new(store: Arc<dyn TupleStore>, wasm_host: Option<Arc<WasmHost>>) -> Self {
        Self { store, wasm_host }
    }

    /// Check if a subject has permission on a resource
    #[instrument(skip(self))]
    pub async fn check(&self, request: CheckRequest) -> Result<Decision> {
        debug!(
            subject = %request.subject,
            resource = %request.resource,
            permission = %request.permission,
            "Evaluating permission check"
        );

        // TODO: Implement full check logic
        // 1. Parse permission definition from IPL
        // 2. Expand relation graph
        // 3. Query tuple store
        // 4. Invoke WASM modules if needed
        // 5. Return decision

        Ok(Decision::Deny)
    }

    /// Expand a relation into its userset tree
    #[instrument(skip(self))]
    pub async fn expand(&self, request: ExpandRequest) -> Result<UsersetTree> {
        debug!(
            resource = %request.resource,
            relation = %request.relation,
            "Expanding userset"
        );

        // TODO: Implement expansion logic
        // 1. Read relation definition
        // 2. Traverse graph recursively
        // 3. Build userset tree

        Ok(UsersetTree {
            node_type: crate::UsersetNodeType::This,
            children: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use infera_store::MemoryBackend;

    #[tokio::test]
    async fn test_evaluator_creation() {
        let store = Arc::new(MemoryBackend::new());
        let evaluator = Evaluator::new(store, None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await;
        assert!(result.is_ok());
    }
}
