//! Parallel evaluation support for relations

use std::sync::Arc;

use inferadb_engine_types::{Decision, EvaluateRequest};
use tokio::task::JoinSet;

use crate::{EvalError, Result, evaluator::Evaluator, ipl::RelationExpr};

/// Parallel evaluator for relation expressions
pub struct ParallelEvaluator {
    /// Maximum number of concurrent evaluations
    max_concurrency: usize,
}

impl Default for ParallelEvaluator {
    fn default() -> Self {
        Self {
            max_concurrency: 10, // Reasonable default
        }
    }
}

impl ParallelEvaluator {
    /// Create a new parallel evaluator with custom concurrency limit
    pub fn new(max_concurrency: usize) -> Self {
        Self { max_concurrency }
    }

    /// Evaluate a union expression in parallel
    pub async fn evaluate_union(
        &self,
        evaluator: Arc<Evaluator>,
        request: EvaluateRequest,
        expressions: &[RelationExpr],
        resource_type: String,
    ) -> Result<Decision> {
        if expressions.is_empty() {
            return Ok(Decision::Deny);
        }

        let mut join_set = JoinSet::new();

        // Spawn tasks for each branch, respecting concurrency limits
        for expr in expressions {
            let eval = evaluator.clone();
            let req = request.clone();
            let expr = expr.clone();
            let res_type = resource_type.clone();

            join_set.spawn(async move {
                Self::evaluate_expression_branch(eval, req, &expr, res_type).await
            });

            // Limit concurrency
            if join_set.len() >= self.max_concurrency {
                // Wait for at least one to complete
                if let Some(result) = join_set.join_next().await {
                    let decision = result
                        .map_err(|e| EvalError::Evaluation(format!("Task join error: {}", e)))??;

                    // For union, if any branch allows, we can return early
                    if decision == Decision::Allow {
                        // Cancel remaining tasks
                        join_set.shutdown().await;
                        return Ok(Decision::Allow);
                    }
                }
            }
        }

        // Wait for all remaining tasks
        while let Some(result) = join_set.join_next().await {
            let decision =
                result.map_err(|e| EvalError::Evaluation(format!("Task join error: {}", e)))??;

            // For union, if any branch allows, return Allow
            if decision == Decision::Allow {
                // Cancel any remaining tasks
                join_set.shutdown().await;
                return Ok(Decision::Allow);
            }
        }

        // All branches denied
        Ok(Decision::Deny)
    }

    /// Evaluate an intersection expression in parallel
    pub async fn evaluate_intersection(
        &self,
        evaluator: Arc<Evaluator>,
        request: EvaluateRequest,
        expressions: &[RelationExpr],
        resource_type: String,
    ) -> Result<Decision> {
        if expressions.is_empty() {
            return Ok(Decision::Deny);
        }

        let mut join_set = JoinSet::new();

        // Spawn tasks for each branch
        for expr in expressions {
            let eval = evaluator.clone();
            let req = request.clone();
            let expr = expr.clone();
            let res_type = resource_type.clone();

            join_set.spawn(async move {
                Self::evaluate_expression_branch(eval, req, &expr, res_type).await
            });

            // Limit concurrency
            if join_set.len() >= self.max_concurrency {
                if let Some(result) = join_set.join_next().await {
                    let decision = result
                        .map_err(|e| EvalError::Evaluation(format!("Task join error: {}", e)))??;

                    // For intersection, if any branch denies, we can return early
                    if decision == Decision::Deny {
                        join_set.shutdown().await;
                        return Ok(Decision::Deny);
                    }
                }
            }
        }

        // Wait for all remaining tasks
        while let Some(result) = join_set.join_next().await {
            let decision =
                result.map_err(|e| EvalError::Evaluation(format!("Task join error: {}", e)))??;

            // For intersection, if any branch denies, return Deny
            if decision == Decision::Deny {
                join_set.shutdown().await;
                return Ok(Decision::Deny);
            }
        }

        // All branches allowed
        Ok(Decision::Allow)
    }

    /// Evaluate an exclusion expression in parallel (base and subtract)
    pub async fn evaluate_exclusion(
        &self,
        evaluator: Arc<Evaluator>,
        request: EvaluateRequest,
        base: &RelationExpr,
        subtract: &RelationExpr,
        resource_type: String,
    ) -> Result<Decision> {
        let eval_base = evaluator.clone();
        let eval_subtract = evaluator.clone();
        let req_base = request.clone();
        let req_subtract = request.clone();
        let base = base.clone();
        let subtract = subtract.clone();
        let res_type_base = resource_type.clone();
        let res_type_subtract = resource_type.clone();

        // Evaluate base and subtract in parallel
        let (base_result, subtract_result) = tokio::join!(
            Self::evaluate_expression_branch(eval_base, req_base, &base, res_type_base),
            Self::evaluate_expression_branch(
                eval_subtract,
                req_subtract,
                &subtract,
                res_type_subtract
            )
        );

        let base_decision = base_result?;
        let subtract_decision = subtract_result?;

        // Exclusion: Allow if base allows AND subtract denies
        if base_decision == Decision::Allow && subtract_decision == Decision::Deny {
            Ok(Decision::Allow)
        } else {
            Ok(Decision::Deny)
        }
    }

    /// Helper to evaluate a single expression branch
    async fn evaluate_expression_branch(
        _evaluator: Arc<Evaluator>,
        _request: EvaluateRequest,
        _expression: &RelationExpr,
        _resource_type: String,
    ) -> Result<Decision> {
        // For now, this is a placeholder that would integrate with the actual evaluator
        // In a real implementation, this would call into the evaluator's relation evaluation logic
        // For MVP, we'll mark this as a simplified version

        // This would need to be integrated with the actual evaluator logic
        // which requires access to the schema and recursive evaluation
        Ok(Decision::Deny)
    }
}

#[cfg(test)]
mod tests {
    use inferadb_engine_repository::EngineStorage;
    use inferadb_storage::MemoryBackend;

    use super::*;
    use crate::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

    async fn create_test_evaluator() -> Arc<Evaluator> {
        let store = Arc::new(EngineStorage::new(MemoryBackend::new()));

        let types = vec![TypeDef::new(
            "document".to_string(),
            vec![RelationDef::new("viewer".to_string(), Some(RelationExpr::This))],
        )];

        let schema = Arc::new(Schema::new(types));
        Arc::new(Evaluator::new(store, schema, None, 0))
    }

    #[tokio::test]
    async fn test_parallel_evaluator_creation() {
        let evaluator = ParallelEvaluator::default();
        assert_eq!(evaluator.max_concurrency, 10);

        let evaluator = ParallelEvaluator::new(5);
        assert_eq!(evaluator.max_concurrency, 5);
    }

    #[tokio::test]
    async fn test_evaluate_union_empty() {
        let parallel_eval = ParallelEvaluator::default();
        let evaluator = create_test_evaluator().await;

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let result =
            parallel_eval.evaluate_union(evaluator, request, &[], "document".to_string()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Decision::Deny);
    }

    #[tokio::test]
    async fn test_evaluate_intersection_empty() {
        let parallel_eval = ParallelEvaluator::default();
        let evaluator = create_test_evaluator().await;

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let result = parallel_eval
            .evaluate_intersection(evaluator, request, &[], "document".to_string())
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Decision::Deny);
    }

    #[tokio::test]
    async fn test_concurrency_limit() {
        let parallel_eval = ParallelEvaluator::new(3);
        assert_eq!(parallel_eval.max_concurrency, 3);
    }
}
