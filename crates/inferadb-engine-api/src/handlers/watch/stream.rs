//! Watch endpoint using Server-Sent Events

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt};
use inferadb_engine_const::scopes::*;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Result,
    content_negotiation::{AcceptHeader, ResponseFormat},
    handlers::utils::auth::authorize_request,
};

/// REST request for Watch endpoint
#[derive(Debug, Deserialize, Serialize)]
pub struct WatchRestRequest {
    /// Optional filter by resource types (e.g., ["document", "folder"])
    /// If empty, watches all relationship changes
    #[serde(default)]
    pub resource_types: Vec<String>,
    /// Optional start cursor/revision to resume from
    /// If None, starts from current point in time
    pub cursor: Option<String>,
}

/// Watch endpoint using Server-Sent Events
///
/// Returns a continuous stream of relationship changes as they occur.
/// The stream remains open indefinitely until the client disconnects.
#[tracing::instrument(skip(state))]
pub async fn watch_handler(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Json(request): Json<WatchRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // Streaming endpoints only support JSON (SSE with JSON payloads)
    if format == ResponseFormat::Toon {
        return Err(ApiError::InvalidRequest(
            "Streaming endpoints do not support TOON format. Use Accept: application/json or text/event-stream".to_string()
        ));
    }

    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, &[SCOPE_WATCH])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!("Watch request from tenant: {} (vault: {})", auth_ctx.organization, vault);
    }

    // Parse cursor (base64 decode to revision)
    let start_revision = if let Some(cursor) = &request.cursor {
        use base64::{Engine as _, engine::general_purpose};
        let decoded = general_purpose::STANDARD
            .decode(cursor)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid cursor: {}", e)))?;
        let revision_str = String::from_utf8(decoded)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid cursor encoding: {}", e)))?;
        let revision_u64 = revision_str
            .parse::<u64>()
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid cursor format: {}", e)))?;
        inferadb_engine_types::Revision(revision_u64)
    } else {
        // Start from next revision
        let current =
            state.store.get_revision(vault).await.map_err(|e| {
                ApiError::Internal(format!("Failed to get current revision: {}", e))
            })?;
        current.next()
    };

    // Use WatchService for the polling logic
    let change_stream =
        state.watch_service.watch_changes(vault, start_revision, request.resource_types);

    // Transform ChangeEvent stream to SSE Event stream
    let stream = change_stream.map(|result| match result {
        Ok(event) => {
            let timestamp = {
                let secs = event.timestamp_nanos / 1_000_000_000;
                let nanos = (event.timestamp_nanos % 1_000_000_000) as u32;
                chrono::DateTime::from_timestamp(secs, nanos)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
            };

            let operation = match event.operation {
                inferadb_engine_types::ChangeOperation::Create => "create",
                inferadb_engine_types::ChangeOperation::Delete => "delete",
            };

            let data = serde_json::json!({
                "operation": operation,
                "relationship": {
                    "resource": event.relationship.resource,
                    "relation": event.relationship.relation,
                    "subject": event.relationship.subject,
                },
                "revision": event.revision.0.to_string(),
                "timestamp": timestamp,
            });

            Event::default().event("change").json_data(data)
        },
        Err(e) => {
            let error_data = serde_json::json!({
                "error": e.to_string()
            });
            Event::default().event("error").json_data(error_data)
        },
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
