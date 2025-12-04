//! Simulate endpoint - run checks with ephemeral context relationships

use std::sync::Arc;

use axum::extract::State;
use infera_const::scopes::*;
use infera_core::Evaluator;
use infera_store::RelationshipStore;
use infera_types::{Decision, EvaluateRequest, Relationship};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Result,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_request,
};

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
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    request: axum::Json<SimulateRequest>,
) -> Result<ResponseData<SimulateResponse>> {
    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, state.default_vault, &[SCOPE_CHECK, SCOPE_SIMULATE])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            "Simulate request from tenant: {} (vault: {})",
            auth_ctx.organization,
            vault
        );
    }

    // Validate context relationships
    if request.0.context_relationships.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one context relationship required".to_string(),
        ));
    }

    for relationship in &request.0.context_relationships {
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
        .write(vault, request.0.context_relationships.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write context relationships: {}", e)))?;

    // Create a temporary evaluator with the ephemeral store
    // Create a minimal schema for simulation (empty schema allows all relations)
    use infera_core::ipl::Schema;
    let temp_schema = Arc::new(Schema { types: Vec::new() });
    let temp_evaluator = Evaluator::new(ephemeral_store.clone(), temp_schema, None, vault);

    // Run the evaluation with the ephemeral data
    let evaluate_request = EvaluateRequest {
        subject: request.0.check.subject,
        resource: request.0.check.resource,
        permission: request.0.check.permission,
        context: request.0.check.context,
        trace: None,
    };

    let decision = temp_evaluator.check(evaluate_request).await?;

    Ok(ResponseData::new(
        SimulateResponse {
            decision,
            context_relationships_count: request.0.context_relationships.len(),
        },
        format,
    ))
}
