//! Helper utilities for integration tests

use infera_core::{CheckRequest, Evaluator};
use infera_store::{MemoryBackend, Tuple, TupleStore};
use infera_core::ipl::Schema;
use std::sync::Arc;

/// Test fixture for setting up a complete evaluation environment
pub struct TestFixture {
    pub store: Arc<MemoryBackend>,
    pub evaluator: Evaluator,
}

impl TestFixture {
    /// Create a new test fixture with the given schema
    pub fn new(schema: Schema) -> Self {
        let store = Arc::new(MemoryBackend::new());
        let evaluator = Evaluator::new(
            store.clone() as Arc<dyn TupleStore>,
            Arc::new(schema),
            None,
        );

        Self { store, evaluator }
    }

    /// Write tuples to the store
    pub async fn write_tuples(&self, tuples: Vec<Tuple>) -> anyhow::Result<()> {
        self.store.write(tuples).await?;
        Ok(())
    }

    /// Perform an authorization check
    pub async fn check(
        &self,
        subject: &str,
        resource: &str,
        permission: &str,
    ) -> anyhow::Result<infera_core::Decision> {
        let request = CheckRequest {
            subject: subject.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            context: None,
        };

        Ok(self.evaluator.check(request).await?)
    }

    /// Assert that a check returns Allow
    pub async fn assert_allowed(&self, subject: &str, resource: &str, permission: &str) {
        let result = self.check(subject, resource, permission).await.unwrap();
        assert_eq!(
            result,
            infera_core::Decision::Allow,
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
            infera_core::Decision::Deny,
            "{} should be denied {} on {}",
            subject,
            permission,
            resource
        );
    }
}

/// Helper to create a tuple
pub fn tuple(object: &str, relation: &str, user: &str) -> Tuple {
    Tuple {
        object: object.to_string(),
        relation: relation.to_string(),
        user: user.to_string(),
    }
}
