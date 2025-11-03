//! List resources endpoint - returns all resources accessible by a subject

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt, stream};
use infera_const::scopes::*;
use infera_types::ListResourcesRequest;
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState, Result};

/// List resources endpoint - returns all resources accessible by a subject
#[derive(Serialize, Deserialize, Debug)]
pub struct ListResourcesRestRequest {
    /// Subject (e.g., "user:alice")
    pub subject: String,
    /// Resource type to filter by (e.g., "document")
    pub resource_type: String,
    /// Permission to check (e.g., "can_view")
    pub permission: String,
    /// Optional limit on number of resources to return
    pub limit: Option<u32>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
    /// Optional resource ID pattern filter (supports wildcards: * and ?)
    /// Examples: "doc:readme*", "user:alice_?", "folder:*/subfolder"
    pub resource_id_pattern: Option<String>,
}

/// Streaming list resources endpoint using Server-Sent Events
///
/// Returns resources as they're discovered, enabling progressive rendering
/// for large result sets.
#[tracing::instrument(skip(state))]
pub async fn list_resources_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ListResourcesRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope (or lookup-resources scope)
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &[SCOPE_CHECK, SCOPE_LIST_RESOURCES],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Streaming list resources request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized("Authentication required".to_string()));
        }
    }

    // Validate request
    if request.subject.is_empty() {
        return Err(ApiError::InvalidRequest("Subject cannot be empty".to_string()));
    }
    if request.resource_type.is_empty() {
        return Err(ApiError::InvalidRequest("Resource type cannot be empty".to_string()));
    }
    if request.permission.is_empty() {
        return Err(ApiError::InvalidRequest("Permission cannot be empty".to_string()));
    }

    // Convert to core request
    let list_request = ListResourcesRequest {
        subject: request.subject,
        resource_type: request.resource_type,
        permission: request.permission,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
        resource_id_pattern: request.resource_id_pattern,
    };

    // Execute the lookup operation
    let response = state.evaluator.list_resources(list_request).await?;

    // Create a stream that sends each resource as a separate SSE event
    let resources = response.resources;
    let cursor = response.cursor;
    let total_count = response.total_count;

    let stream = stream::iter(resources.into_iter().enumerate().map(|(idx, resource)| {
        let data = serde_json::json!({
            "resource": resource,
            "index": idx,
        });

        Event::default().json_data(data)
    }))
    .chain(stream::once(async move {
        // Send final summary event
        let summary = serde_json::json!({
            "cursor": cursor,
            "total_count": total_count,
            "complete": true
        });

        Event::default().event("summary").json_data(summary)
    }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
