//! Snapshot reads at specific revisions
//!
//! Provides snapshot isolation for reads at specific revision tokens.
//! Supports multi-vault operations for tenant isolation.

use std::{sync::Arc, time::Duration};

use inferadb_engine_store::RelationshipStore;
use inferadb_engine_types::{Relationship, RelationshipKey, Revision};

/// Type alias for vault identifiers
type VaultId = i64;
use tokio::time::timeout;

use crate::{ReplError, Result, RevisionToken};

/// Snapshot reader for consistent reads at a specific revision
pub struct SnapshotReader {
    store: Arc<dyn RelationshipStore>,
    timeout_duration: Duration,
}

impl SnapshotReader {
    /// Create a new snapshot reader
    pub fn new(store: Arc<dyn RelationshipStore>) -> Self {
        Self { store, timeout_duration: Duration::from_secs(30) }
    }

    /// Create a snapshot reader with a custom timeout
    pub fn with_timeout(store: Arc<dyn RelationshipStore>, timeout_duration: Duration) -> Self {
        Self { store, timeout_duration }
    }

    /// Read relationships at a specific revision token
    ///
    /// Blocks until the revision is available or times out.
    ///
    /// # Arguments
    /// * `vault` - The vault ID for tenant isolation
    /// * `key` - The relationship key to query
    /// * `token` - The revision token specifying the snapshot point
    pub async fn read_at_token(
        &self,
        vault: VaultId,
        key: &RelationshipKey,
        token: &RevisionToken,
    ) -> Result<Vec<Relationship>> {
        // Validate the token
        token.validate()?;

        // Extract the revision from the token
        // For a single-node system, use the token's revision directly
        // For multi-node, we'd need more complex logic
        let revision = Revision(token.revision);

        // Attempt to read at the specified revision with timeout
        let result =
            timeout(self.timeout_duration, self.wait_for_revision_and_read(vault, key, revision))
                .await;

        match result {
            Ok(Ok(relationships)) => Ok(relationships),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ReplError::Replication(
                "Timeout waiting for revision to become available".to_string(),
            )),
        }
    }

    /// Wait for a revision to be available, then read
    async fn wait_for_revision_and_read(
        &self,
        vault: VaultId,
        key: &RelationshipKey,
        target_revision: Revision,
    ) -> Result<Vec<Relationship>> {
        // Poll until the store has reached the target revision
        loop {
            let current_revision = self.store.get_revision(vault).await?;

            if current_revision >= target_revision {
                // Revision is available, perform the read
                let relationships = self.store.read(vault, key, target_revision).await?;
                return Ok(relationships);
            }

            // Wait a bit before checking again
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Read relationships at the current revision
    ///
    /// # Arguments
    /// * `vault` - The vault ID for tenant isolation
    /// * `key` - The relationship key to query
    pub async fn read_current(
        &self,
        vault: VaultId,
        key: &RelationshipKey,
    ) -> Result<Vec<Relationship>> {
        let current_revision = self.store.get_revision(vault).await?;
        let relationships = self.store.read(vault, key, current_revision).await?;
        Ok(relationships)
    }

    /// Get the current revision as a token
    ///
    /// # Arguments
    /// * `vault` - The vault ID for tenant isolation
    /// * `node_id` - The identifier for this node
    pub async fn current_token(&self, vault: VaultId, node_id: String) -> Result<RevisionToken> {
        let revision = self.store.get_revision(vault).await?;
        Ok(RevisionToken::new(node_id, revision.0))
    }
}

#[cfg(test)]
mod tests {
    use inferadb_engine_store::MemoryBackend;
    use inferadb_engine_types::Relationship;

    use super::*;

    const TEST_VAULT: VaultId = 0;
    const OTHER_VAULT: VaultId = 1;

    #[tokio::test]
    async fn test_read_current() {
        let store = Arc::new(MemoryBackend::new());
        let reader = SnapshotReader::new(store.clone());

        // Write a relationship
        let relationship = Relationship {
            vault: TEST_VAULT,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        store.write(TEST_VAULT, vec![relationship.clone()]).await.unwrap();

        // Read at current revision
        let key = RelationshipKey {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let relationships = reader.read_current(TEST_VAULT, &key).await.unwrap();

        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0], relationship);
    }

    #[tokio::test]
    async fn test_read_at_token() {
        let store = Arc::new(MemoryBackend::new());
        let reader = SnapshotReader::new(store.clone());

        // Write first relationship
        let relationship1 = Relationship {
            vault: TEST_VAULT,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let rev1 = store.write(TEST_VAULT, vec![relationship1.clone()]).await.unwrap();

        // Create token at revision 1
        let token1 = RevisionToken::new("node1".to_string(), rev1.0);

        // Write second relationship
        let relationship2 = Relationship {
            vault: TEST_VAULT,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
        };
        store.write(TEST_VAULT, vec![relationship2.clone()]).await.unwrap();

        // Read at revision 1 (should only see first relationship)
        let key = RelationshipKey {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let relationships = reader.read_at_token(TEST_VAULT, &key, &token1).await.unwrap();

        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0], relationship1);
    }

    #[tokio::test]
    async fn test_current_token() {
        let store = Arc::new(MemoryBackend::new());
        let reader = SnapshotReader::new(store.clone());

        // Write a relationship
        let relationship = Relationship {
            vault: TEST_VAULT,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let revision = store.write(TEST_VAULT, vec![relationship]).await.unwrap();

        // Get current token
        let token = reader.current_token(TEST_VAULT, "node1".to_string()).await.unwrap();

        assert_eq!(token.node_id, "node1");
        assert_eq!(token.revision, revision.0);
    }

    #[tokio::test]
    async fn test_timeout_on_unavailable_revision() {
        let store = Arc::new(MemoryBackend::new());
        let reader = SnapshotReader::with_timeout(store.clone(), Duration::from_millis(100));

        // Create a token with a future revision that will never be reached
        let token = RevisionToken::new("node1".to_string(), 999);

        let key = RelationshipKey {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };

        // This should timeout
        let result = reader.read_at_token(TEST_VAULT, &key, &token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multi_vault_isolation() {
        let store = Arc::new(MemoryBackend::new());
        let reader = SnapshotReader::new(store.clone());

        // Write relationships to different vaults
        let relationship1 = Relationship {
            vault: TEST_VAULT,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let relationship2 = Relationship {
            vault: OTHER_VAULT,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
        };

        store.write(TEST_VAULT, vec![relationship1.clone()]).await.unwrap();
        store.write(OTHER_VAULT, vec![relationship2.clone()]).await.unwrap();

        // Read from TEST_VAULT should only see alice
        let key = RelationshipKey {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let relationships = reader.read_current(TEST_VAULT, &key).await.unwrap();
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].subject, "user:alice");

        // Read from OTHER_VAULT should only see bob
        let relationships = reader.read_current(OTHER_VAULT, &key).await.unwrap();
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].subject, "user:bob");
    }

    #[tokio::test]
    async fn test_vault_revision_independence() {
        let store = Arc::new(MemoryBackend::new());
        let reader = SnapshotReader::new(store.clone());

        // Write to TEST_VAULT
        let relationship1 = Relationship {
            vault: TEST_VAULT,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        store.write(TEST_VAULT, vec![relationship1]).await.unwrap();

        // Get tokens for both vaults
        let token1 = reader.current_token(TEST_VAULT, "node1".to_string()).await.unwrap();
        let token2 = reader.current_token(OTHER_VAULT, "node1".to_string()).await.unwrap();

        // Revisions should be independent per vault
        // TEST_VAULT has had a write, OTHER_VAULT is still at initial revision
        assert!(token1.revision >= 1);
        assert_eq!(token2.revision, 0);
    }
}
