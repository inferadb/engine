//! Helper utilities for integration tests

#![allow(dead_code)] // Some test files use subsets of these utilities

use std::sync::Arc;

use inferadb_engine_core::{Evaluator, ipl::Schema};
use inferadb_engine_repository::EngineStorage;
use inferadb_engine_store::RelationshipStore;
// Re-export for use in tests
pub use inferadb_engine_types::Relationship;
use inferadb_engine_types::{Decision, EvaluateRequest};
use inferadb_engine_wasm::WasmHost;
use inferadb_storage::MemoryBackend;

/// Test fixture for setting up a complete evaluation environment
pub struct TestFixture {
    pub store: Arc<EngineStorage<MemoryBackend>>,
    pub evaluator: Evaluator,
}

impl TestFixture {
    /// Create a new test fixture with the given schema
    pub fn new(schema: Schema) -> Self {
        let store = Arc::new(EngineStorage::new(MemoryBackend::new()));
        let evaluator = Evaluator::new(
            store.clone() as Arc<dyn RelationshipStore>,
            Arc::new(schema),
            None,
            0i64,
        );

        Self { store, evaluator }
    }

    /// Create a new test fixture with the given schema and WASM host
    pub fn new_with_wasm(schema: Schema, wasm_host: Arc<WasmHost>) -> Self {
        let store = Arc::new(EngineStorage::new(MemoryBackend::new()));
        let evaluator = Evaluator::new(
            store.clone() as Arc<dyn RelationshipStore>,
            Arc::new(schema),
            Some(wasm_host),
            0i64,
        );

        Self { store, evaluator }
    }

    /// Write relationships to the store
    pub async fn write_relationships(
        &self,
        relationships: Vec<Relationship>,
    ) -> anyhow::Result<()> {
        self.store.write(0i64, relationships).await?;
        Ok(())
    }

    /// Perform an authorization check
    pub async fn check(
        &self,
        subject: &str,
        resource: &str,
        permission: &str,
    ) -> anyhow::Result<Decision> {
        let request = EvaluateRequest {
            subject: subject.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            context: None,
            trace: None,
        };

        Ok(self.evaluator.check(request).await?)
    }

    /// Assert that a check returns Allow
    pub async fn assert_allowed(&self, subject: &str, resource: &str, permission: &str) {
        let result = self.check(subject, resource, permission).await.unwrap();
        assert_eq!(
            result,
            Decision::Allow,
            "{} should be allowed {} on {}",
            subject,
            permission,
            resource
        );
    }

    /// Assert that a check returns Deny
    pub async fn assert_denied(&self, subject: &str, resource: &str, permission: &str) {
        let result = self.check(subject, resource, permission).await.unwrap();
        assert_eq!(
            result,
            Decision::Deny,
            "{} should be denied {} on {}",
            subject,
            permission,
            resource
        );
    }
}

/// Helper function to create a relationship with vault set to nil
pub fn relationship(resource: &str, relation: &str, subject: &str) -> Relationship {
    Relationship {
        vault: 0i64,
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: subject.to_string(),
    }
}
