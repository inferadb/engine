//! List relationships endpoint - returns relationships matching optional filters
//!
//! This is a thin protocol adapter that converts REST requests to service calls.

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt, stream};
use infera_const::scopes::*;
use infera_types::ListRelationshipsRequest;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Result,
    content_negotiation::{AcceptHeader, ResponseFormat},
    handlers::utils::auth::authorize_request,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct ListRelationshipsRestRequest {
    /// Optional filter by resource (e.g., "doc:readme")
    pub resource: Option<String>,
    /// Optional filter by relation (e.g., "viewer")
    pub relation: Option<String>,
    /// Optional filter by subject (e.g., "user:alice")
    pub subject: Option<String>,
    /// Optional limit on number of relationships to return (default: 100, max: 1000)
    pub limit: Option<u32>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
}

/// Streaming list relationships endpoint using Server-Sent Events
///
/// Returns relationships as they're discovered, enabling progressive rendering
/// for large result sets.
#[tracing::instrument(skip(state))]
pub async fn list_relationships_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Json(request): Json<ListRelationshipsRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // Streaming endpoints only support JSON (SSE with JSON payloads)
    if format == ResponseFormat::Toon {
        return Err(ApiError::InvalidRequest(
            "Streaming endpoints do not support TOON format. Use Accept: application/json or text/event-stream".to_string()
        ));
    }

    // Authorize request and extract vault
    let vault = authorize_request(
        &auth.0,
        state.default_vault,
        state.config.auth.enabled,
        &[SCOPE_CHECK, SCOPE_LIST_RELATIONSHIPS],
    )?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            "Streaming list relationships request from tenant: {} (vault: {})",
            auth_ctx.tenant_id,
            vault
        );
    }

    // Convert to core request (all filters are optional)
    let list_request = ListRelationshipsRequest {
        resource: request.resource,
        relation: request.relation,
        subject: request.subject,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
    };

    // Execute the list operation using relationship service (handles validation)
    let response = state.relationship_service.list_relationships(vault, list_request).await?;

    // Response already uses Relationship type with resource/subject
    let relationships = response.relationships;
    let cursor = response.cursor;
    let total_count = response.total_count;

    let stream = stream::iter(relationships.into_iter().enumerate().map(|(idx, relationship)| {
        let data = serde_json::json!({
            "relationship": relationship,
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
