//! Delete relationships endpoint

use axum::{Json, extract::State};
use infera_const::scopes::*;
use infera_types::{DeleteFilter, Relationship, RelationshipKey};
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState, Result, handlers::utils::auth::authorize_request};

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteRequest {
    /// Optional filter for bulk deletion
    /// If provided, all relationships matching the filter will be deleted
    pub filter: Option<DeleteFilter>,
    /// Optional exact relationships to delete
    /// Can be combined with filter
    pub relationships: Option<Vec<Relationship>>,
    /// Maximum number of relationships to delete (safety limit)
    /// If not specified, uses default limit (1000) for filter-based deletes
    /// Set to 0 for unlimited (use with extreme caution!)
    pub limit: Option<usize>,
    /// Optional expected revision for optimistic locking
    /// If provided, the delete will only succeed if the current store revision matches
    pub expected_revision: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteResponse {
    pub revision: String,
    pub relationships_deleted: usize,
}

/// Delete relationships endpoint
#[tracing::instrument(skip(state))]
pub async fn delete_relationships_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>> {
    // Authorize request and extract vault
    let vault =
        authorize_request(&auth.0, state.default_vault, state.config.auth.enabled, &[SCOPE_WRITE])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            vault = %vault,
            tenant_id = %auth_ctx.tenant_id,
            "Delete request from tenant"
        );
    }

    // Validate that at least one deletion method is specified
    let has_filter = request.filter.is_some();
    let has_relationships = request.relationships.as_ref().is_some_and(|r| !r.is_empty());

    if !has_filter && !has_relationships {
        return Err(ApiError::InvalidRequest(
            "Must provide either filter or relationships to delete".to_string(),
        ));
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

    let mut total_deleted = 0;
    let mut last_revision = None;
    let mut affected_resources = std::collections::HashSet::new();

    // Handle filter-based deletion if filter is provided
    if let Some(filter) = request.filter {
        // Validate filter is not empty
        if filter.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Filter must have at least one field set to avoid deleting all relationships"
                    .to_string(),
            ));
        }

        // Apply default limit of 1000 if not specified, 0 means unlimited
        let limit = match request.limit {
            Some(0) => None,    // 0 means unlimited
            Some(n) => Some(n), // Explicit limit
            None => Some(1000), // Default limit
        };

        // Track affected resources for cache invalidation
        if let Some(ref resource) = filter.resource {
            affected_resources.insert(resource.clone());
        }

        // Perform batch deletion
        let (revision, count) = state
            .store
            .delete_by_filter(vault, &filter, limit)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to delete by filter: {}", e)))?;

        last_revision = Some(revision);
        total_deleted += count;
    }

    // Handle exact relationship deletion if relationships are provided
    if let Some(relationships) = request.relationships {
        if !relationships.is_empty() {
            // Validate and convert relationships to RelationshipKeys
            let mut keys = Vec::new();
            for relationship in &relationships {
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

                // Track resource for cache invalidation
                affected_resources.insert(relationship.resource.clone());

                keys.push(RelationshipKey {
                    resource: relationship.resource.clone(),
                    relation: relationship.relation.clone(),
                    subject: Some(relationship.subject.clone()),
                });
            }

            // Delete relationships from store
            for key in keys {
                match state.store.delete(vault, &key).await {
                    Ok(revision) => {
                        last_revision = Some(revision);
                        total_deleted += 1;
                    },
                    Err(e) => {
                        tracing::warn!("Failed to delete relationship {:?}: {}", key, e);
                        // Continue deleting other relationships even if one fails
                    },
                }
            }
        }
    }

    // Return the last revision from successful deletes
    let revision = last_revision
        .ok_or_else(|| ApiError::Internal("No relationships were deleted".to_string()))?;

    // Invalidate cache for affected resources
    let resources_vec: Vec<String> = affected_resources.into_iter().collect();
    state.relationship_service.invalidate_cache_for_resources(&resources_vec).await;

    Ok(Json(DeleteResponse {
        revision: revision.0.to_string(),
        relationships_deleted: total_deleted,
    }))
}
