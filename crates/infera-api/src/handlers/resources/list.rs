//! List resources endpoint - returns all resources accessible by a subject
//!
//! This is a thin protocol adapter that converts REST requests to service calls.

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt, stream};
use infera_const::scopes::*;
use infera_types::ListResourcesRequest;
use serde::{Deserialize, Serialize};

use crate::{AppState, Result, handlers::utils::auth::authorize_request};

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
    // Authorize request and extract vault
    let vault = authorize_request(
        &auth.0,
        state.default_vault,
        state.config.auth.enabled,
        &[SCOPE_CHECK, SCOPE_LIST_RESOURCES],
    )?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            "Streaming list resources request from tenant: {} (vault: {})",
            auth_ctx.tenant_id,
            vault
        );
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

    // Execute the list operation using resource service (handles validation)
    let response = state.resource_service.list_resources(vault, list_request).await?;

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
