//! List subjects endpoint - returns subjects with access to a resource

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt, stream};
use infera_const::scopes::*;
use infera_types::ListSubjectsRequest;
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState, Result};

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
    State(state): State<AppState>,
    Json(request): Json<ListSubjectsRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(auth_ctx) = auth.0 {
            // Require inferadb.check scope (or list-subjects scope)
            infera_auth::middleware::require_any_scope(
                &auth_ctx,
                &[SCOPE_CHECK, SCOPE_LIST_SUBJECTS],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!("Streaming list subjects request from tenant: {}", auth_ctx.tenant_id);
        } else {
            return Err(ApiError::Unauthorized("Authentication required".to_string()));
        }
    }

    // Convert to core request
    let list_request = ListSubjectsRequest {
        resource: request.resource,
        relation: request.relation,
        subject_type: request.subject_type,
        limit: request.limit.map(|l| l as usize),
        cursor: request.cursor,
    };

    // Execute the list operation
    let response = state.evaluator.list_subjects(list_request).await?;

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
