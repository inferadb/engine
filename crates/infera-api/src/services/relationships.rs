//! Relationship service - handles relationship management operations

use std::sync::Arc;

use infera_cache::AuthCache;
use infera_core::{Evaluator, ipl::Schema};
use infera_store::RelationshipStore;
use infera_types::{
    DeleteFilter, DeleteResponse, ListRelationshipsRequest, ListRelationshipsResponse,
    Relationship, Revision,
};
use infera_wasm::WasmHost;
use uuid::Uuid;

use super::validation::{
    validate_delete_filter, validate_list_relationships_request, validate_relationship,
};
use crate::ApiError;

/// Service for managing relationships
///
/// This service handles the business logic for creating, deleting, and listing
/// relationships. It is protocol-agnostic and used by gRPC, REST, and AuthZEN handlers.
pub struct RelationshipService {
    store: Arc<dyn RelationshipStore>,
    schema: Arc<Schema>,
    wasm_host: Option<Arc<WasmHost>>,
    cache: Option<Arc<AuthCache>>,
}

impl RelationshipService {
    /// Creates a new relationship service
    pub fn new(
        store: Arc<dyn RelationshipStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
        cache: Option<Arc<AuthCache>>,
    ) -> Self {
        Self { store, schema, wasm_host, cache }
    }

    /// Writes relationships to the store
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `relationships` - Vector of relationships to write
    ///
    /// # Returns
    /// The new revision number after the write
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if any relationship is invalid
    /// Returns `ApiError::Internal` if the write fails
    #[tracing::instrument(skip(self, relationships), fields(vault = %vault, count = relationships.len()))]
    pub async fn write_relationships(
        &self,
        vault: Uuid,
        mut relationships: Vec<Relationship>,
    ) -> Result<Revision, ApiError> {
        if relationships.is_empty() {
            return Err(ApiError::InvalidRequest(
                "At least one relationship must be provided".to_string(),
            ));
        }

        tracing::debug!("Writing {} relationships", relationships.len());

        // Validate all relationships
        for relationship in &relationships {
            validate_relationship(relationship)?;
        }

        // Set vault on all relationships
        for relationship in &mut relationships {
            relationship.vault = vault;
        }

        // Write to store
        let revision = self
            .store
            .write(vault, relationships)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to write relationships: {}", e)))?;

        tracing::debug!(revision = ?revision, "Relationships written successfully");

        Ok(revision)
    }

    /// Deletes relationships matching a filter
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `filter` - The delete filter specifying which relationships to delete
    /// * `limit` - Optional maximum number of relationships to delete (0 = unlimited)
    ///
    /// # Returns
    /// The delete response containing count and new revision
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if the filter is invalid
    /// Returns `ApiError::Internal` if the delete fails
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn delete_relationships(
        &self,
        vault: Uuid,
        filter: DeleteFilter,
        limit: Option<usize>,
    ) -> Result<DeleteResponse, ApiError> {
        // Validate filter
        validate_delete_filter(&filter)?;

        tracing::debug!(
            resource = ?filter.resource,
            relation = ?filter.relation,
            subject = ?filter.subject,
            limit = ?limit,
            "Deleting relationships"
        );

        // Delete from store
        let (revision, relationships_deleted) =
            self.store.delete_by_filter(vault, &filter, limit).await.map_err(|e| {
                ApiError::Internal(format!("Failed to delete relationships: {}", e))
            })?;

        tracing::debug!(
            relationships_deleted = relationships_deleted,
            revision = ?revision,
            "Relationships deleted successfully"
        );

        Ok(DeleteResponse { revision, relationships_deleted })
    }

    /// Lists relationships matching optional filters
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `request` - The list request with optional filters
    ///
    /// # Returns
    /// A list of relationships and optional pagination cursor
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if the request is invalid
    /// Returns `ApiError::Internal` if the operation fails
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn list_relationships(
        &self,
        vault: Uuid,
        request: ListRelationshipsRequest,
    ) -> Result<ListRelationshipsResponse, ApiError> {
        // Validate request
        validate_list_relationships_request(&request)?;

        tracing::debug!(
            resource = ?request.resource,
            relation = ?request.relation,
            subject = ?request.subject,
            limit = ?request.limit,
            "Listing relationships"
        );

        // Create vault-scoped evaluator
        let evaluator = Arc::new(Evaluator::new_with_cache(
            Arc::clone(&self.store),
            Arc::clone(&self.schema),
            self.wasm_host.clone(),
            self.cache.clone(),
            vault,
        ));

        // Execute list operation
        let response = evaluator
            .list_relationships(request)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to list relationships: {}", e)))?;

        tracing::debug!(
            relationship_count = response.relationships.len(),
            has_cursor = response.cursor.is_some(),
            "Relationship listing completed"
        );

        Ok(response)
    }

    /// Invalidates cache entries for specific resources
    ///
    /// This should be called after relationship writes or deletes to ensure
    /// authorization decisions are re-evaluated with the latest data.
    ///
    /// # Arguments
    /// * `resources` - List of resource identifiers to invalidate
    #[tracing::instrument(skip(self))]
    pub async fn invalidate_cache_for_resources(&self, resources: &[String]) {
        if let Some(cache) = &self.cache {
            cache.invalidate_resources(resources).await;
            tracing::debug!(resource_count = resources.len(), "Cache invalidated for resources");
        }
    }

    /// Invalidates all cache entries for a specific vault
    ///
    /// This provides a way to do complete cache invalidation for a vault,
    /// useful for bulk operations or administrative tasks.
    ///
    /// # Arguments
    /// * `vault` - The vault ID to invalidate cache for
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn invalidate_cache_for_vault(&self, vault: Uuid) {
        if let Some(cache) = &self.cache {
            cache.invalidate_vault(vault).await;
            tracing::debug!("Cache invalidated for entire vault");
        }
    }
}

#[cfg(test)]
mod tests {
    use infera_core::ipl::{RelationDef, RelationExpr, TypeDef};
    use infera_store::MemoryBackend;

    use super::*;

    async fn create_test_service() -> (RelationshipService, Uuid) {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());

        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "viewer".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        let vault = Uuid::new_v4();
        let service = RelationshipService::new(store, schema, None, None);

        (service, vault)
    }

    #[tokio::test]
    async fn test_write_relationships() {
        let (service, vault) = create_test_service().await;

        let relationships = vec![Relationship {
            vault,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }];

        let revision = service.write_relationships(vault, relationships).await.unwrap();
        assert!(revision.0 > 0);
    }

    #[tokio::test]
    async fn test_write_empty_relationships() {
        let (service, vault) = create_test_service().await;

        let result = service.write_relationships(vault, vec![]).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn test_write_invalid_relationship() {
        let (service, vault) = create_test_service().await;

        let relationships = vec![Relationship {
            vault,
            resource: "".to_string(), // Invalid
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }];

        let result = service.write_relationships(vault, relationships).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn test_delete_relationships() {
        let (service, vault) = create_test_service().await;

        // First write some relationships
        let relationships = vec![
            Relationship {
                vault,
                resource: "document:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "document:guide".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
        ];

        service.write_relationships(vault, relationships).await.unwrap();

        // Delete relationships
        let filter = DeleteFilter {
            resource: None,
            relation: None,
            subject: Some("user:alice".to_string()),
        };

        let result = service.delete_relationships(vault, filter, None).await.unwrap();
        assert_eq!(result.relationships_deleted, 2);
    }

    #[tokio::test]
    async fn test_list_relationships() {
        let (service, vault) = create_test_service().await;

        // Write test relationships
        let relationships = vec![
            Relationship {
                vault,
                resource: "document:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "document:guide".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            },
        ];

        service.write_relationships(vault, relationships).await.unwrap();

        // List all relationships
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: None,
            limit: None,
            cursor: None,
        };

        let response = service.list_relationships(vault, request).await.unwrap();
        assert_eq!(response.relationships.len(), 2);
    }

    #[tokio::test]
    async fn test_list_relationships_with_filter() {
        let (service, vault) = create_test_service().await;

        // Write test relationships
        let relationships = vec![
            Relationship {
                vault,
                resource: "document:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "document:guide".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            },
        ];

        service.write_relationships(vault, relationships).await.unwrap();

        // List with subject filter
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: Some("user:alice".to_string()),
            limit: None,
            cursor: None,
        };

        let response = service.list_relationships(vault, request).await.unwrap();
        assert_eq!(response.relationships.len(), 1);
        assert_eq!(response.relationships[0].subject, "user:alice");
    }

    #[tokio::test]
    async fn test_vault_isolation() {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "viewer".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        let vault_a = Uuid::new_v4();
        let vault_b = Uuid::new_v4();

        let service = RelationshipService::new(store, schema, None, None);

        // Write to vault A
        let relationships = vec![Relationship {
            vault: vault_a,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }];

        service.write_relationships(vault_a, relationships).await.unwrap();

        // List from vault A
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: None,
            limit: None,
            cursor: None,
        };

        let response_a = service.list_relationships(vault_a, request.clone()).await.unwrap();
        assert_eq!(response_a.relationships.len(), 1);

        // List from vault B should be empty (vault isolation)
        let response_b = service.list_relationships(vault_b, request).await.unwrap();
        assert_eq!(response_b.relationships.len(), 0);
    }
}
