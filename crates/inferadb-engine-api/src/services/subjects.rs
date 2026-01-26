//! Subject service - handles subject listing operations

use std::sync::Arc;

use inferadb_engine_types::{ListSubjectsRequest, ListSubjectsResponse};

use super::ServiceContext;
use super::validation::validate_list_subjects_request;
use crate::ApiError;

/// Service for listing subjects that have access to resources
///
/// This service handles the business logic for discovering which subjects
/// have a specific relation to a resource. It is protocol-agnostic and used
/// by gRPC, REST, and AuthZEN handlers.
pub struct SubjectService {
    context: Arc<ServiceContext>,
}

impl SubjectService {
    /// Creates a new subject service
    pub fn new(context: Arc<ServiceContext>) -> Self {
        Self { context }
    }

    /// Lists subjects that have a relation to a resource
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `request` - The list subjects request containing resource, relation, and optional subject
    ///   type filter
    ///
    /// # Returns
    /// A list of subject IDs and optional pagination cursor
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if the request is invalid
    /// Returns `ApiError::Internal` if the operation fails
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn list_subjects(
        &self,
        vault: i64,
        request: ListSubjectsRequest,
    ) -> Result<ListSubjectsResponse, ApiError> {
        // Validate request
        validate_list_subjects_request(&request)?;

        tracing::debug!(
            resource = %request.resource,
            relation = %request.relation,
            subject_type = ?request.subject_type,
            limit = ?request.limit,
            "Listing subjects"
        );

        // Create vault-scoped evaluator for proper multi-tenant isolation
        let evaluator = self.context.create_evaluator(vault);

        // Execute list operation
        let response = evaluator
            .list_subjects(request)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to list subjects: {}", e)))?;

        tracing::debug!(
            subject_count = response.subjects.len(),
            has_cursor = response.cursor.is_some(),
            "Subject listing completed"
        );

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_engine_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
    use inferadb_engine_repository::EngineStorage;
    use inferadb_engine_store::RelationshipStore;
    use inferadb_engine_types::Relationship;
    use inferadb_storage::MemoryBackend;

    use super::*;

    async fn create_test_service() -> (SubjectService, i64) {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());

        // Create a schema with document type and view relation
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
                    Relationship {
                        vault,
                        resource: "document:secret".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:alice".to_string(),
                    },
                ],
            )
            .await
            .unwrap();

        let context = Arc::new(ServiceContext::builder().store(store).schema(schema).build());
        let service = SubjectService::new(context);

        (service, vault)
    }

    #[tokio::test]
    async fn test_list_subjects() {
        let (service, vault) = create_test_service().await;

        let request = ListSubjectsRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = service.list_subjects(vault, request).await.unwrap();

        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"user:alice".to_string()));
        assert!(response.subjects.contains(&"user:bob".to_string()));
    }

    #[tokio::test]
    async fn test_list_subjects_no_matches() {
        let (service, vault) = create_test_service().await;

        let request = ListSubjectsRequest {
            resource: "document:nonexistent".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = service.list_subjects(vault, request).await.unwrap();

        assert_eq!(response.subjects.len(), 0);
    }

    #[tokio::test]
    async fn test_list_subjects_with_type_filter() {
        let (service, vault) = create_test_service().await;

        let request = ListSubjectsRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject_type: Some("user".to_string()),
            limit: None,
            cursor: None,
        };

        let response = service.list_subjects(vault, request).await.unwrap();

        assert_eq!(response.subjects.len(), 2);
        // Verify all subjects are of type "user"
        for subject in &response.subjects {
            assert!(subject.starts_with("user:"));
        }
    }

    #[tokio::test]
    async fn test_list_subjects_with_limit() {
        let (service, vault) = create_test_service().await;

        let request = ListSubjectsRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: Some(1),
            cursor: None,
        };

        let response = service.list_subjects(vault, request).await.unwrap();

        assert_eq!(response.subjects.len(), 1);
        assert!(response.cursor.is_some()); // Should have cursor for pagination
    }

    #[tokio::test]
    async fn test_validate_empty_resource() {
        let (service, vault) = create_test_service().await;

        let request = ListSubjectsRequest {
            resource: "".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let result = service.list_subjects(vault, request).await;
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
        let service = SubjectService::new(context);

        let request = ListSubjectsRequest {
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        // Vault A should return subjects
        let response_a = service.list_subjects(vault_a, request.clone()).await.unwrap();
        assert_eq!(response_a.subjects.len(), 1);

        // Vault B should return empty (vault isolation)
        let response_b = service.list_subjects(vault_b, request).await.unwrap();
        assert_eq!(response_b.subjects.len(), 0);
    }
}
