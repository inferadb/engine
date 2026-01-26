//! Resource service - handles resource listing operations

use std::sync::Arc;

use inferadb_engine_types::{ListResourcesRequest, ListResourcesResponse};

use super::{ServiceContext, validation::validate_list_resources_request};
use crate::ApiError;

/// Service for listing resources accessible to subjects
///
/// This service handles the business logic for discovering which resources
/// a subject can access with a given permission. It is protocol-agnostic
/// and used by gRPC, REST, and AuthZEN handlers.
pub struct ResourceService {
    context: Arc<ServiceContext>,
}

impl ResourceService {
    /// Creates a new resource service
    pub fn new(context: Arc<ServiceContext>) -> Self {
        Self { context }
    }

    /// Lists resources accessible to a subject
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `request` - The list resources request containing subject, resource type, and permission
    ///
    /// # Returns
    /// A list of resource IDs and optional pagination cursor
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if the request is invalid
    /// Returns `ApiError::Internal` if the operation fails
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn list_resources(
        &self,
        vault: i64,
        request: ListResourcesRequest,
    ) -> Result<ListResourcesResponse, ApiError> {
        // Validate request
        validate_list_resources_request(&request)?;

        tracing::debug!(
            subject = %request.subject,
            resource_type = %request.resource_type,
            permission = %request.permission,
            limit = ?request.limit,
            "Listing resources"
        );

        // Create vault-scoped evaluator for proper multi-tenant isolation
        let evaluator = self.context.create_evaluator(vault);

        // Execute list operation
        let response = evaluator
            .list_resources(request)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to list resources: {}", e)))?;

        tracing::debug!(
            resource_count = response.resources.len(),
            has_cursor = response.cursor.is_some(),
            "Resource listing completed"
        );

        Ok(response)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
    use inferadb_engine_repository::EngineStorage;
    use inferadb_engine_store::RelationshipStore;
    use inferadb_engine_types::Relationship;
    use inferadb_storage::MemoryBackend;

    use super::*;

    async fn create_test_service() -> (ResourceService, i64) {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

        // Create a schema with document type and view permission
        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "viewer".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        let vault = 12345678901234i64;

        // Add test relationships
        store
            .write(
                vault,
                vec![
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
                    Relationship {
                        vault,
                        resource: "document:secret".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:bob".to_string(),
                    },
                ],
            )
            .await
            .unwrap();

        let context = Arc::new(ServiceContext::builder().store(store).schema(schema).build());
        let service = ResourceService::new(context);

        (service, vault)
    }

    #[tokio::test]
    async fn test_list_resources() {
        let (service, vault) = create_test_service().await;

        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "document".to_string(),
            permission: "viewer".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        let response = service.list_resources(vault, request).await.unwrap();

        assert_eq!(response.resources.len(), 2);
        assert!(response.resources.contains(&"document:readme".to_string()));
        assert!(response.resources.contains(&"document:guide".to_string()));
    }

    #[tokio::test]
    async fn test_list_resources_no_matches() {
        let (service, vault) = create_test_service().await;

        let request = ListResourcesRequest {
            subject: "user:charlie".to_string(),
            resource_type: "document".to_string(),
            permission: "viewer".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        let response = service.list_resources(vault, request).await.unwrap();

        assert_eq!(response.resources.len(), 0);
    }

    #[tokio::test]
    async fn test_list_resources_with_limit() {
        let (service, vault) = create_test_service().await;

        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "document".to_string(),
            permission: "viewer".to_string(),
            limit: Some(1),
            cursor: None,
            resource_id_pattern: None,
        };

        let response = service.list_resources(vault, request).await.unwrap();

        assert_eq!(response.resources.len(), 1);
        assert!(response.cursor.is_some()); // Should have cursor for pagination
    }

    #[tokio::test]
    async fn test_validate_empty_subject() {
        let (service, vault) = create_test_service().await;

        let request = ListResourcesRequest {
            subject: "".to_string(),
            resource_type: "document".to_string(),
            permission: "viewer".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        let result = service.list_resources(vault, request).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn test_vault_isolation() {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "viewer".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        let vault_a = 11111111111111i64;
        let vault_b = 22222222222222i64;

        // Add relationship to vault A only
        store
            .write(
                vault_a,
                vec![Relationship {
                    vault: vault_a,
                    resource: "document:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                }],
            )
            .await
            .unwrap();

        let context = Arc::new(ServiceContext::builder().store(store).schema(schema).build());
        let service = ResourceService::new(context);

        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "document".to_string(),
            permission: "viewer".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        // Vault A should return resources
        let response_a = service.list_resources(vault_a, request.clone()).await.unwrap();
        assert_eq!(response_a.resources.len(), 1);

        // Vault B should return empty (vault isolation)
        let response_b = service.list_resources(vault_b, request).await.unwrap();
        assert_eq!(response_b.resources.len(), 0);
    }
}
