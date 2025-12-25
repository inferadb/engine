use std::sync::Arc;

use inferadb_engine_store::RelationshipStore;
use inferadb_engine_types::{AuthContext, EvaluateRequest as CoreEvaluateRequest, Relationship};
use tonic::{Request, Response, Status};

use super::{
    AuthorizationServiceImpl,
    proto::{SimulateRequest, SimulateResponse},
};

pub async fn simulate(
    _service: &AuthorizationServiceImpl,
    request: Request<SimulateRequest>,
) -> Result<Response<SimulateResponse>, Status> {
    // Extract vault from request extensions (set by auth middleware)
    // Authentication is always required
    let vault = request
        .extensions()
        .get::<Arc<AuthContext>>()
        .map(|ctx| ctx.vault)
        .ok_or_else(|| Status::unauthenticated("Authentication required"))?;

    let request = request.into_inner();

    // Validate context relationships
    if request.context_relationships.is_empty() {
        return Err(Status::invalid_argument("At least one context relationship required"));
    }

    // Extract check from request
    let check = request.check.ok_or_else(|| Status::invalid_argument("Check is required"))?;

    // Convert proto relationships to core Relationship type
    let context_relationships: Vec<Relationship> = request
        .context_relationships
        .into_iter()
        .map(|rel| Relationship {
            vault,
            resource: rel.resource,
            relation: rel.relation,
            subject: rel.subject,
        })
        .collect();

    // Validate relationships
    for relationship in &context_relationships {
        if relationship.resource.is_empty()
            || relationship.relation.is_empty()
            || relationship.subject.is_empty()
        {
            return Err(Status::invalid_argument("Invalid relationship format"));
        }
    }

    // Create an ephemeral in-memory store with ONLY the context relationships
    use inferadb_engine_store::MemoryBackend;
    let ephemeral_store = Arc::new(MemoryBackend::new());

    // Write context relationships to ephemeral store
    ephemeral_store
        .write(vault, context_relationships.clone())
        .await
        .map_err(|e| Status::internal(format!("Failed to write context relationships: {}", e)))?;

    // Create a temporary evaluator with the ephemeral store
    use inferadb_engine_core::{Evaluator, ipl::Schema};
    let temp_schema = Arc::new(Schema { types: Vec::new() });
    let temp_evaluator = Evaluator::new(ephemeral_store.clone(), temp_schema, None, vault);

    // Parse context string to JSON if provided
    let context = if let Some(ctx_str) = check.context {
        Some(
            serde_json::from_str(&ctx_str)
                .map_err(|e| Status::invalid_argument(format!("Invalid context JSON: {}", e)))?,
        )
    } else {
        None
    };

    // Run the evaluation with the ephemeral data
    let evaluate_request = CoreEvaluateRequest {
        subject: check.subject,
        resource: check.resource,
        permission: check.permission,
        context,
        trace: None,
    };

    let decision = temp_evaluator
        .check(evaluate_request)
        .await
        .map_err(|e| Status::internal(format!("Evaluation failed: {}", e)))?;

    Ok(Response::new(SimulateResponse {
        decision: decision as i32,
        context_relationships_count: context_relationships.len() as u64,
    }))
}
