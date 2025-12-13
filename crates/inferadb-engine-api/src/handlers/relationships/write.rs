//! Write relationships endpoint
//!
//! This is a thin protocol adapter that converts REST requests to service calls.

use axum::extract::State;
use inferadb_engine_const::scopes::*;
use inferadb_engine_types::Relationship;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Result,
    content_negotiation::{AcceptHeader, ResponseData},
    handlers::utils::auth::authorize_request,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteRequest {
    pub relationships: Vec<Relationship>,
    /// Optional expected revision for optimistic locking
    /// If provided, the write will only succeed if the current store revision matches
    pub expected_revision: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteResponse {
    pub revision: String,
    pub relationships_written: usize,
}

/// Write relationships endpoint
#[tracing::instrument(skip(state))]
pub async fn write_relationships_handler(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    axum::Json(request): axum::Json<WriteRequest>,
) -> Result<ResponseData<WriteResponse>> {
    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, &[SCOPE_WRITE])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            vault = %vault,
            tenant_id = %auth_ctx.organization,
            "Write request from tenant"
        );
    }

    // Set vault on all relationships
    let mut relationships = request.relationships;
    for relationship in &mut relationships {
        relationship.vault = vault;
    }

    // Optimistic locking: Check expected revision if provided
    // Note: This is a REST-specific feature not in the service layer
    if let Some(expected_rev) = &request.expected_revision {
        let current_rev = state
            .store
            .get_revision(vault)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to get revision: {}", e)))?;

        let current_rev_str = current_rev.0.to_string();
        if &current_rev_str != expected_rev {
            return Err(ApiError::RevisionMismatch {
                expected: expected_rev.clone(),
                actual: current_rev_str,
            });
        }
    }

    // Write relationships using relationship service (handles validation)
    let revision =
        state.relationship_service.write_relationships(vault, relationships.clone()).await?;

    // Invalidate cache for affected resources
    let affected_resources: Vec<String> =
        relationships.iter().map(|r| r.resource.clone()).collect();
    state.relationship_service.invalidate_cache_for_resources(&affected_resources).await;

    Ok(ResponseData::new(
        WriteResponse {
            revision: revision.0.to_string(), // Extract the u64 value
            relationships_written: relationships.len(),
        },
        format,
    ))
}
