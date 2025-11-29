//! List subjects endpoint - returns subjects with access to a resource
//!
//! This is a thin protocol adapter that converts REST requests to service calls.

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt, stream};
use infera_const::scopes::*;
use infera_types::ListSubjectsRequest;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Result,
    content_negotiation::{AcceptHeader, ResponseFormat},
    handlers::utils::auth::authorize_request,
};

/// Request format for the list subjects REST endpoint
#[derive(Debug, Deserialize, Serialize)]
pub struct ListSubjectsRestRequest {
    /// Resource (e.g., "document:readme")
    pub resource: String,
    /// Relation to check (e.g., "viewer")
    pub relation: String,
    /// Optional filter by subject type (e.g., "user", "group")
    pub subject_type: Option<String>,
    /// Optional limit on number of subjects to return (default: 100, max: 1000)
    pub limit: Option<u32>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
}

/// Streaming list subjects endpoint using Server-Sent Events
///
/// Returns subjects as they're discovered, enabling progressive rendering
/// for large result sets.
#[tracing::instrument(skip(state))]
pub async fn list_subjects_stream_handler(
    auth: infera_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Json(request): Json<ListSubjectsRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // Streaming endpoints only support JSON (SSE with JSON payloads)
    if format == ResponseFormat::Toon {
        return Err(ApiError::InvalidRequest(
            "Streaming endpoints do not support TOON format. Use Accept: application/json or text/event-stream".to_string()
        ));
    }

    // Authorize request and extract vault
    let vault =
        authorize_request(&auth.0, state.default_vault, &[SCOPE_CHECK, SCOPE_LIST_SUBJECTS])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            "Streaming list subjects request from tenant: {} (vault: {})",
            auth_ctx.organization,
            vault
        );
    }

    // Convert to core request
    let list_request = ListSubjectsRequest {
        resource: request.resource,
        relation: request.relation,
        subject_type: request.subject_type,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
    };

    // Execute the list operation using subject service (handles validation)
    let response = state.subject_service.list_subjects(vault, list_request).await?;

    let subjects = response.subjects;
    let cursor = response.cursor;
    let total_count = response.total_count;

    let stream = stream::iter(subjects.into_iter().enumerate().map(|(idx, subject)| {
        let data = serde_json::json!({
            "subject": subject,
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
