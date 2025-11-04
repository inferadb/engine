//! Expansion service - handles relationship graph expansion

use std::sync::Arc;

use infera_core::{Evaluator, ipl::Schema};
use infera_store::RelationshipStore;
use infera_types::{ExpandRequest, ExpandResponse};
use infera_wasm::WasmHost;
use uuid::Uuid;

use crate::ApiError;

/// Service for expanding relationship graphs
///
/// This service handles the business logic for expanding relationship trees
/// to discover all subjects that have a specific permission on a resource.
/// It is protocol-agnostic and used by gRPC, REST, and AuthZEN handlers.
pub struct ExpansionService {
    store: Arc<dyn RelationshipStore>,
    schema: Arc<Schema>,
    wasm_host: Option<Arc<WasmHost>>,
}

impl ExpansionService {
    /// Creates a new expansion service
    pub fn new(
        store: Arc<dyn RelationshipStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
    ) -> Self {
        Self { store, schema, wasm_host }
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
        vault: Uuid,
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
        let evaluator = Arc::new(Evaluator::new(
            Arc::clone(&self.store),
            Arc::clone(&self.schema),
            self.wasm_host.clone(),
            vault,
        ));

        // Execute expansion
        let response = evaluator
            .expand(request)
            .await
            .map_err(|e| ApiError::Internal(format!("Expansion failed: {}", e)))?;

        tracing::debug!(
            user_count = response.users.len(),
            has_continuation_token = response.continuation_token.is_some(),
            "Expansion completed"
        );

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use infera_core::ipl::{RelationDef, RelationExpr, TypeDef};
    use infera_store::MemoryBackend;
    use infera_types::Relationship;

    async fn create_test_service() -> (ExpansionService, Uuid) {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());

        // Create a schema with document type and viewer relation
        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "viewer".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        let vault = Uuid::new_v4();

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

        let service = ExpansionService::new(store, schema, None);

        (service, vault)
    }

    #[tokio::test]
    async fn test_expand() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            cursor: None,
        };

        let response = service.expand(vault, request).await.unwrap();

        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"user:alice".to_string()));
        assert!(response.subjects.contains(&"user:bob".to_string()));
    }

    #[tokio::test]
    async fn test_expand_no_matches() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "document:nonexistent".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            cursor: None,
        };

        let response = service.expand(vault, request).await.unwrap();

        assert_eq!(response.subjects.len(), 0);
    }

    #[tokio::test]
    async fn test_expand_with_limit() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            limit: Some(1),
            cursor: None,
        };

        let response = service.expand(vault, request).await.unwrap();

        assert_eq!(response.subjects.len(), 1);
        assert!(response.cursor.is_some()); // Should have cursor for pagination
    }

    #[tokio::test]
    async fn test_validate_empty_resource() {
        let (service, vault) = create_test_service().await;

        let request = ExpandRequest {
            resource: "".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            cursor: None,
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
            cursor: None,
        };

        let result = service.expand(vault, request).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::InvalidRequest(_))));
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

        let service = ExpansionService::new(store, schema, None);

        let request = ExpandRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            limit: None,
            cursor: None,
        };

        // Vault A should return subjects
        let response_a = service.expand(vault_a, request.clone()).await.unwrap();
        assert_eq!(response_a.subjects.len(), 1);

        // Vault B should return empty (vault isolation)
        let response_b = service.expand(vault_b, request).await.unwrap();
        assert_eq!(response_b.subjects.len(), 0);
    }
}
