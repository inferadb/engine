//! Simulate endpoint - run checks with ephemeral context relationships

use std::sync::Arc;

use axum::{Json, extract::State};
use infera_core::Evaluator;
use infera_store::RelationshipStore;
use infera_types::{Decision, EvaluateRequest, Relationship};
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState, Result, handlers::utils::auth::get_vault};

#[derive(Serialize, Deserialize, Debug)]
pub struct SimulateRequest {
    pub context_relationships: Vec<Relationship>,
    pub check: SimulateCheck,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SimulateCheck {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SimulateResponse {
    pub decision: Decision,
    pub context_relationships_count: usize,
}

/// Simulate endpoint - run checks with ephemeral context relationships
#[tracing::instrument(skip(state))]
pub async fn simulate_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>> {
    // Extract vault from auth context or use default
    let vault = get_vault(&auth.0, state.default_vault);

    // Validate vault access (basic nil check)
    if let Some(ref auth_ctx) = auth.0 {
        infera_auth::validate_vault_access(auth_ctx)
            .map_err(|e| ApiError::Forbidden(format!("Vault access denied: {}", e)))?;
    }

    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(ref auth_ctx) = auth.0 {
            // Require inferadb.check scope for simulation
            infera_auth::middleware::require_any_scope(
                auth_ctx,
                &["inferadb.check", "inferadb.simulate"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!(
                "Simulate request from tenant: {} (vault: {})",
                auth_ctx.tenant_id,
                vault
            );
        } else {
            return Err(ApiError::Unauthorized("Authentication required".to_string()));
        }
    }

    // Validate context relationships
    if request.context_relationships.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one context relationship required".to_string(),
        ));
    }

    for relationship in &request.context_relationships {
        if relationship.resource.is_empty()
            || relationship.relation.is_empty()
            || relationship.subject.is_empty()
        {
            return Err(ApiError::InvalidRequest("Invalid relationship format".to_string()));
        }
    }

    // Create an ephemeral in-memory store with ONLY the context relationships
    // This simulates authorization decisions with temporary/what-if data
    use infera_store::MemoryBackend;
    let ephemeral_store = Arc::new(MemoryBackend::new());

    // Write context relationships to ephemeral store
    ephemeral_store
        .write(vault, request.context_relationships.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write context relationships: {}", e)))?;

    // Create a temporary evaluator with the ephemeral store
    // Create a minimal schema for simulation (empty schema allows all relations)
    use infera_core::ipl::Schema;
    let temp_schema = Arc::new(Schema { types: Vec::new() });
    let temp_evaluator = Evaluator::new(ephemeral_store.clone(), temp_schema, None, vault);

    // Run the evaluation with the ephemeral data
    let evaluate_request = EvaluateRequest {
        subject: request.check.subject,
        resource: request.check.resource,
        permission: request.check.permission,
        context: request.check.context,
        trace: None,
    };

    let decision = temp_evaluator.check(evaluate_request).await?;

    Ok(Json(SimulateResponse {
        decision,
        context_relationships_count: request.context_relationships.len(),
    }))
}
