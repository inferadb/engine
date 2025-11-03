//! Write relationships endpoint

use axum::{Json, extract::State};
use infera_types::Relationship;
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState, Result, handlers::utils::auth::authorize_request};

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
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<WriteRequest>,
) -> Result<Json<WriteResponse>> {
    // Authorize request and extract vault
    let vault = authorize_request(
        &auth.0,
        state.default_vault,
        state.config.auth.enabled,
        &["inferadb.write"],
    )?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            vault = %vault,
            tenant_id = %auth_ctx.tenant_id,
            "Write request from tenant"
        );
    }

    // Validate request
    if request.relationships.is_empty() {
        return Err(ApiError::InvalidRequest("No relationships provided".to_string()));
    }

    // Set vault on all relationships and validate format
    let mut relationships = request.relationships;
    for relationship in &mut relationships {
        // Set vault to ensure consistency
        relationship.vault = vault;

        if relationship.resource.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Relationship resource cannot be empty".to_string(),
            ));
        }
        if relationship.relation.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Relationship relation cannot be empty".to_string(),
            ));
        }
        if relationship.subject.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Relationship subject cannot be empty".to_string(),
            ));
        }
        // Validate format (should contain colon)
        if !relationship.resource.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid object format '{}': must be 'type:id'",
                relationship.resource
            )));
        }
        if !relationship.subject.contains(':') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid user format '{}': must be 'type:id'",
                relationship.subject
            )));
        }
        // Validate wildcard placement (wildcards only allowed in subject position as "type:*")
        if let Err(err) = relationship.validate_wildcard_placement() {
            return Err(ApiError::InvalidRequest(err));
        }
    }

    // Optimistic locking: Check expected revision if provided
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

    // Write relationships to store
    let revision = state
        .store
        .write(vault, relationships.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write relationships: {}", e)))?;

    // Invalidate cache for affected resources in this vault
    if let Some(cache) = state.evaluator.cache() {
        let affected_resources =
            infera_cache::AuthCache::extract_affected_resources(&relationships);
        cache.invalidate_vault_resources(vault, &affected_resources).await;
        tracing::debug!(
            vault = %vault,
            resources_invalidated = affected_resources.len(),
            "Cache invalidated for affected resources"
        );
    }

    Ok(Json(WriteResponse {
        revision: revision.0.to_string(), // Extract the u64 value
        relationships_written: relationships.len(),
    }))
}
