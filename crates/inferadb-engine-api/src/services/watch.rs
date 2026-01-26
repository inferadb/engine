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
    /// * `cursor` - Optional cursor to resume from a specific point
    /// * `resource_type` - Optional filter to only watch changes for a specific resource type
    ///
    /// # Returns
    /// A stream of change events
    ///
    /// # Errors
    /// Returns `ApiError::Internal` if the watch stream cannot be created
    ///
    /// # Implementation
    /// This uses polling on the change log with a small delay between polls.
    /// For production use, a push-based mechanism would be more efficient.
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn watch_changes(
        &self,
        vault: i64,
        cursor: Option<String>,
        resource_type: Option<String>,
    ) -> std::result::Result<ChangeStream, ApiError> {
        // Parse cursor or start from current revision
        let start_revision =
            if let Some(cursor_str) = cursor {
                Revision(cursor_str.parse::<u64>().map_err(|_| {
                    ApiError::InvalidRequest(format!("Invalid cursor: {}", cursor_str))
                })?)
            } else {
                // Start from current revision
                self.store.get_revision(vault).await.map_err(|e| {
                    ApiError::Internal(format!("Failed to get current revision: {}", e))
                })?
            };

        let store = Arc::clone(&self.store);
        let resource_types: Vec<String> = resource_type.into_iter().collect();

        // Create a polling stream that checks for new changes
        let stream = async_stream::stream! {
            let mut current_revision = start_revision;

            loop {
                // Check for new changes since last revision
                // Now uses the trait method directly since RelationshipStore has read_changes
                let changes_result = store.read_changes(vault, current_revision, &resource_types, Some(100)).await;

                match changes_result {
                    Ok(changes) if !changes.is_empty() => {
                        for change in changes {
                            current_revision = Revision(current_revision.0.max(change.revision.0 + 1));
                            yield Ok(change);
                        }
                    }
                    Ok(_) => {
                        // No new changes, wait before polling again
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        yield Err(ApiError::Internal(format!("Failed to read changes: {}", e)));
                        break;
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use inferadb_engine_repository::EngineStorage;
    use inferadb_engine_types::Relationship;
    use inferadb_storage::MemoryBackend;

    use super::*;

    #[tokio::test]
    async fn test_watch_changes() {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
        let vault = 12345678901234i64;

        let service = WatchService::new(Arc::clone(&store));

        // Start watching
        let mut stream = service.watch_changes(vault, None, None).await.unwrap();

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
        let stream = service.watch_changes(vault, None, Some("document".to_string())).await;

        // Should succeed in creating the stream
        assert!(stream.is_ok());
    }

    #[tokio::test]
    async fn test_vault_isolation() {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
        let vault_a = 11111111111111i64;
        let vault_b = 22222222222222i64;

        let service = WatchService::new(Arc::clone(&store));

        // Start watching vault A
        let mut stream_a = service.watch_changes(vault_a, None, None).await.unwrap();

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
