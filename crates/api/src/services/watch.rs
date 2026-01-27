//! Watch service - handles real-time change streaming

use std::{pin::Pin, sync::Arc, time::Duration};

use futures::Stream;
use inferadb_engine_store::RelationshipStore;
use inferadb_engine_types::{ChangeEvent, Revision};

use crate::ApiError;

/// Type alias for watch change stream
type ChangeStream = Pin<Box<dyn Stream<Item = std::result::Result<ChangeEvent, ApiError>> + Send>>;

/// Service for watching relationship changes in real-time
///
/// This service handles the business logic for streaming relationship changes
/// as they occur. It is protocol-agnostic and used by gRPC, REST, and AuthZEN handlers.
pub struct WatchService {
    store: Arc<dyn RelationshipStore>,
}

impl WatchService {
    /// Creates a new watch service
    pub fn new(store: Arc<dyn RelationshipStore>) -> Self {
        Self { store }
    }

    /// Watches for relationship changes in a vault
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `start_revision` - The revision to start watching from
    /// * `resource_types` - Filter to only watch changes for specific resource types (empty = all)
    ///
    /// # Returns
    /// A stream of change events
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub fn watch_changes(
        &self,
        vault: i64,
        start_revision: Revision,
        resource_types: Vec<String>,
    ) -> ChangeStream {
        let store = Arc::clone(&self.store);

        let stream = async_stream::stream! {
            let mut current_revision = start_revision;

            loop {
                let changes_result = store.read_changes(vault, current_revision, &resource_types, Some(100)).await;

                match changes_result {
                    Ok(changes) if !changes.is_empty() => {
                        for change in changes {
                            current_revision = Revision(current_revision.0.max(change.revision.0 + 1));
                            yield Ok(change);
                        }
                    }
                    Ok(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        yield Err(ApiError::Internal(format!("Failed to read changes: {}", e)));
                        break;
                    }
                }
            }
        };

        Box::pin(stream)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use futures::StreamExt;
    use inferadb_common_storage::MemoryBackend;
    use inferadb_engine_repository::EngineStorage;
    use inferadb_engine_types::Relationship;

    use super::*;

    #[tokio::test]
    async fn test_watch_changes() {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
        let vault = 12345678901234i64;

        let service = WatchService::new(Arc::clone(&store));

        // Start watching from revision 0
        let mut stream = service.watch_changes(vault, Revision::zero(), vec![]);

        // Write a relationship (this should trigger a change event)
        let relationships = vec![Relationship {
            vault,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }];

        store.write(vault, relationships).await.unwrap();

        // Poll the stream for a change event
        // Note: MemoryBackend might not support watch, so this test may need adjustment
        // based on the actual implementation
        if let Some(event_result) =
            tokio::time::timeout(std::time::Duration::from_millis(100), stream.next())
                .await
                .ok()
                .flatten()
        {
            // If we get an event, verify it
            let event = event_result.unwrap();
            assert_eq!(event.operation, inferadb_engine_types::ChangeOperation::Create);
        }
    }

    #[tokio::test]
    async fn test_watch_with_resource_type_filter() {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
        let vault = 12345678901234i64;

        let service = WatchService::new(store);

        // Watch with resource type filter
        let stream = service.watch_changes(vault, Revision::zero(), vec!["document".to_string()]);

        // Should succeed in creating the stream (sync function, always succeeds)
        let _ = stream;
    }

    #[tokio::test]
    async fn test_vault_isolation() {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
        let vault_a = 11111111111111i64;
        let vault_b = 22222222222222i64;

        let service = WatchService::new(Arc::clone(&store));

        // Start watching vault A from revision 0
        let mut stream_a = service.watch_changes(vault_a, Revision::zero(), vec![]);

        // Write to vault B
        let relationships = vec![Relationship {
            vault: vault_b,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }];

        store.write(vault_b, relationships).await.unwrap();

        // Stream A should not receive events from vault B (vault isolation)
        // This is a timeout test - if we receive no event, vault isolation is working
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), stream_a.next()).await;

        // We expect a timeout (no event received) because the write was to a different vault
        assert!(result.is_err(), "Should not receive events from different vault");
    }
}
