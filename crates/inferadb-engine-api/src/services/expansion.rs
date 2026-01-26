//! Expansion service - handles relationship graph expansion

use std::sync::Arc;

use inferadb_engine_types::{ExpandRequest, ExpandResponse};

use super::ServiceContext;
use crate::ApiError;

/// Service for expanding relationship graphs
///
/// This service handles the business logic for expanding relationship trees
/// to discover all subjects that have a specific permission on a resource.
/// It is protocol-agnostic and used by gRPC, REST, and AuthZEN handlers.
pub struct ExpansionService {
    context: Arc<ServiceContext>,
}

impl ExpansionService {
    /// Creates a new expansion service
    pub fn new(context: Arc<ServiceContext>) -> Self {
        Self { context }
    }

    /// Expands a relationship graph
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `request` - The expand request containing resource, relation, and optional pagination
    ///
    /// # Returns
    /// An expansion response with the user set tree and subjects
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if the request is invalid
    /// Returns `ApiError::Internal` if the expansion fails
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn expand(
        &self,
        vault: i64,
        request: ExpandRequest,
    ) -> Result<ExpandResponse, ApiError> {
        // Validate request
        if request.resource.is_empty() {
            return Err(ApiError::InvalidRequest("Resource cannot be empty".to_string()));
        }
        if request.relation.is_empty() {
            return Err(ApiError::InvalidRequest("Relation cannot be empty".to_string()));
        }

        // Validate resource format
        if !request.resource.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Resource must be in format 'type:id', got: '{}'",
                request.resource
            )));
        }

        tracing::debug!(
            resource = %request.resource,
            relation = %request.relation,
            limit = ?request.limit,
            "Expanding relationship graph"
        );

        // Create vault-scoped evaluator for proper multi-tenant isolation
        let evaluator = self.context.create_evaluator(vault);

        // Execute expansion
        let response = evaluator.expand(request.clone()).await.map_err(|e| {
            tracing::error!("Expansion failed: {}", e);
            ApiError::Internal(format!("Expansion failed: {}", e))
        })?;

        tracing::debug!(
            user_count = response.users.len(),
            has_continuation_token = response.continuation_token.is_some(),
            tree_nodes = ?response.tree,
            "Expansion completed"
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

    async fn create_test_service() -> (ExpansionService, i64) {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

        // Create a schema with document type and viewer relation
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
                        resource: "document:readme".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:bob".to_string(),
                    },
                ],
            )
            .await
            .unwrap();

        let context = Arc::new(ServiceContext::builder().store(store).schema(schema).build());
        let service = ExpansionService::new(context);

        (service, vault)
    }

    #[tokio::test]
    async fn test_expand() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            continuation_token: None,
        };

        let response = service.expand(vault, request).await.unwrap();

        assert_eq!(response.users.len(), 2);
        assert!(response.users.contains(&"user:alice".to_string()));
        assert!(response.users.contains(&"user:bob".to_string()));
    }

    #[tokio::test]
    async fn test_expand_no_matches() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "document:nonexistent".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            continuation_token: None,
        };

        let response = service.expand(vault, request).await.unwrap();

        assert_eq!(response.users.len(), 0);
    }

    #[tokio::test]
    async fn test_expand_with_limit() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            limit: Some(1),
            continuation_token: None,
        };

        let response = service.expand(vault, request).await.unwrap();

        assert_eq!(response.users.len(), 1);
        assert!(response.continuation_token.is_some()); // Should have cursor for pagination
    }

    #[tokio::test]
    async fn test_validate_empty_resource() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            continuation_token: None,
        };

        let result = service.expand(vault, request).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn test_validate_invalid_resource_format() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "invalid".to_string(), // Missing colon
            relation: "viewer".to_string(),
            limit: None,
            continuation_token: None,
        };

        let result = service.expand(vault, request).await;
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
        let service = ExpansionService::new(context);

        let request = ExpandRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            continuation_token: None,
        };

        // Vault A should return users
        let response_a = service.expand(vault_a, request.clone()).await.unwrap();
        assert_eq!(response_a.users.len(), 1);

        // Vault B should return empty (vault isolation)
        let response_b = service.expand(vault_b, request).await.unwrap();
        assert_eq!(response_b.users.len(), 0);
    }
}
