//! Evaluation service - handles authorization decision evaluation

use std::sync::Arc;

use infera_cache::AuthCache;
use infera_core::{DecisionTrace, Evaluator, ipl::Schema};
use infera_store::RelationshipStore;
use infera_types::{Decision, EvaluateRequest};
use infera_wasm::WasmHost;

use super::validation::validate_evaluate_request;
use crate::ApiError;

/// Service for evaluating authorization decisions
///
/// This service handles the core business logic for authorization evaluation,
/// including vault-scoped evaluator creation, request validation, and decision
/// execution. It is protocol-agnostic and used by gRPC, REST, and AuthZEN handlers.
pub struct EvaluationService {
    store: Arc<dyn RelationshipStore>,
    schema: Arc<Schema>,
    wasm_host: Option<Arc<WasmHost>>,
    cache: Option<Arc<AuthCache>>,
}

impl EvaluationService {
    /// Creates a new evaluation service
    pub fn new(
        store: Arc<dyn RelationshipStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
        cache: Option<Arc<AuthCache>>,
    ) -> Self {
        Self { store, schema, wasm_host, cache }
    }

    /// Evaluates a single authorization request
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `request` - The evaluation request containing subject, resource, and permission
    ///
    /// # Returns
    /// The authorization decision (Allow or Deny)
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if the request is invalid
    /// Returns `ApiError::Internal` if the evaluation fails
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn evaluate(
        &self,
        vault: i64,
        request: EvaluateRequest,
    ) -> Result<Decision, ApiError> {
        // Validate request
        validate_evaluate_request(&request)?;

        tracing::debug!(
            subject = %request.subject,
            resource = %request.resource,
            permission = %request.permission,
            "Evaluating authorization request"
        );

        // Create vault-scoped evaluator for proper multi-tenant isolation
        let evaluator = Arc::new(Evaluator::new_with_cache(
            Arc::clone(&self.store),
            Arc::clone(&self.schema),
            self.wasm_host.clone(),
            self.cache.clone(),
            vault,
        ));

        // Execute evaluation
        let decision = evaluator
            .check(request)
            .await
            .map_err(|e| ApiError::Internal(format!("Evaluation failed: {}", e)))?;

        tracing::debug!(decision = ?decision, "Evaluation completed");

        Ok(decision)
    }

    /// Evaluates a request with detailed trace information
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `request` - The evaluation request
    ///
    /// # Returns
    /// A decision trace containing the decision, evaluation tree, and performance metrics
    ///
    /// # Errors
    /// Returns `ApiError::InvalidRequest` if the request is invalid
    /// Returns `ApiError::Internal` if the evaluation fails
    #[tracing::instrument(skip(self), fields(vault = %vault))]
    pub async fn evaluate_with_trace(
        &self,
        vault: i64,
        request: EvaluateRequest,
    ) -> Result<DecisionTrace, ApiError> {
        // Validate request
        validate_evaluate_request(&request)?;

        tracing::debug!(
            subject = %request.subject,
            resource = %request.resource,
            permission = %request.permission,
            "Evaluating authorization request with trace"
        );

        // Create vault-scoped evaluator
        let evaluator = Arc::new(Evaluator::new_with_cache(
            Arc::clone(&self.store),
            Arc::clone(&self.schema),
            self.wasm_host.clone(),
            self.cache.clone(),
            vault,
        ));

        // Execute evaluation with trace
        let trace = evaluator
            .check_with_trace(request)
            .await
            .map_err(|e| ApiError::Internal(format!("Evaluation with trace failed: {}", e)))?;

        tracing::debug!(
            decision = ?trace.decision,
            duration_micros = trace.duration.as_micros(),
            relationships_read = trace.relationships_read,
            "Evaluation with trace completed"
        );

        Ok(trace)
    }

    /// Evaluates multiple requests in batch
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `requests` - Vector of evaluation requests
    ///
    /// # Returns
    /// Vector of results, preserving input order. Each result is either a Decision or an error.
    ///
    /// # Notes
    /// This method evaluates all requests even if some fail. Individual failures are returned
    /// in the result vector rather than failing the entire batch.
    #[tracing::instrument(skip(self, requests), fields(vault = %vault, batch_size = requests.len()))]
    pub async fn evaluate_batch(
        &self,
        vault: i64,
        requests: Vec<EvaluateRequest>,
    ) -> Vec<Result<Decision, ApiError>> {
        tracing::debug!("Evaluating batch of {} requests", requests.len());

        let mut results = Vec::with_capacity(requests.len());

        for request in requests {
            let result = self.evaluate(vault, request).await;
            results.push(result);
        }

        tracing::debug!("Batch evaluation completed");

        results
    }

    /// Evaluates multiple requests with trace information
    ///
    /// # Arguments
    /// * `vault` - The vault ID for multi-tenant isolation
    /// * `requests` - Vector of evaluation requests
    ///
    /// # Returns
    /// Vector of results with trace information, preserving input order
    #[tracing::instrument(skip(self, requests), fields(vault = %vault, batch_size = requests.len()))]
    pub async fn evaluate_batch_with_trace(
        &self,
        vault: i64,
        requests: Vec<EvaluateRequest>,
    ) -> Vec<Result<DecisionTrace, ApiError>> {
        tracing::debug!("Evaluating batch with trace of {} requests", requests.len());

        let mut results = Vec::with_capacity(requests.len());

        for request in requests {
            let result = self.evaluate_with_trace(vault, request).await;
            results.push(result);
        }

        tracing::debug!("Batch evaluation with trace completed");

        results
    }
}

#[cfg(test)]
mod tests {
    use infera_core::ipl::{RelationDef, RelationExpr, TypeDef};
    use infera_store::MemoryBackend;
    use infera_types::Relationship;

    use super::*;

    async fn create_test_service() -> (EvaluationService, i64) {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());

        // Create a simple schema with document type and view permission
        let schema = Arc::new(Schema::new(vec![TypeDef {
            name: "document".to_string(),
            relations: vec![RelationDef {
                name: "viewer".to_string(),
                expr: Some(RelationExpr::This),
            }],
            forbids: vec![],
        }]));

        let vault = 12345678901234i64;

        // Add test relationship
        store
            .write(
                vault,
                vec![Relationship {
                    vault,
                    resource: "document:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                }],
            )
            .await
            .unwrap();

        let service = EvaluationService::new(store, schema, None, None);

        (service, vault)
    }

    #[tokio::test]
    async fn test_evaluate_allow() {
        let (service, vault) = create_test_service().await;

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let decision = service.evaluate(vault, request).await.unwrap();
        assert_eq!(decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_evaluate_deny() {
        let (service, vault) = create_test_service().await;

        let request = EvaluateRequest {
            subject: "user:bob".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let decision = service.evaluate(vault, request).await.unwrap();
        assert_eq!(decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_evaluate_with_trace() {
        let (service, vault) = create_test_service().await;

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let trace = service.evaluate_with_trace(vault, request).await.unwrap();
        assert_eq!(trace.decision, Decision::Allow);
        assert!(trace.duration.as_micros() > 0);
    }

    #[tokio::test]
    async fn test_validate_empty_subject() {
        let (service, vault) = create_test_service().await;

        let request = EvaluateRequest {
            subject: "".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let result = service.evaluate(vault, request).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn test_evaluate_batch() {
        let (service, vault) = create_test_service().await;

        let requests = vec![
            EvaluateRequest {
                subject: "user:alice".to_string(),
                resource: "document:readme".to_string(),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            },
            EvaluateRequest {
                subject: "user:bob".to_string(),
                resource: "document:readme".to_string(),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            },
        ];

        let results = service.evaluate_batch(vault, requests).await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap(), &Decision::Allow);
        assert_eq!(results[1].as_ref().unwrap(), &Decision::Deny);
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

        let vault_a = 11111111111111i64;
        let vault_b = 22222222222222i64;

        // Add relationship to vault A
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

        let service = EvaluationService::new(store, schema, None, None);

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        // Vault A should allow
        let decision_a = service.evaluate(vault_a, request.clone()).await.unwrap();
        assert_eq!(decision_a, Decision::Allow);

        // Vault B should deny (vault isolation)
        let decision_b = service.evaluate(vault_b, request).await.unwrap();
        assert_eq!(decision_b, Decision::Deny);
    }
}
