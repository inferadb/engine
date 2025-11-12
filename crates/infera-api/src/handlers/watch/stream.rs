//! Watch endpoint using Server-Sent Events

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::Stream;
use infera_const::scopes::*;
use infera_store::RelationshipStore;
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
    auth: infera_auth::extractor::OptionalAuth,
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
    let vault =
        authorize_request(&auth.0, state.default_vault, state.config.auth.enabled, &[SCOPE_WATCH])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!("Watch request from tenant: {} (vault: {})", auth_ctx.tenant_id, vault);
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
        infera_types::Revision(revision_u64)
    } else {
        // Start from next revision
        let current =
            state.store.get_revision(vault).await.map_err(|e| {
                ApiError::Internal(format!("Failed to get current revision: {}", e))
            })?;
        current.next()
    };

    let resource_types = request.resource_types;
    let store: Arc<dyn RelationshipStore> = Arc::clone(&state.store) as Arc<dyn RelationshipStore>;

    // Create a continuous polling stream
    let stream = async_stream::stream! {
        let mut last_revision = start_revision;

        loop {
            // Read changes from the change log
            match store.read_changes(vault, last_revision, &resource_types, Some(100)).await {
                Ok(events) => {
                    for event in &events {
                        // Format timestamp as ISO 8601
                        let timestamp = {
                            let secs = event.timestamp_nanos / 1_000_000_000;
                            let nanos = (event.timestamp_nanos % 1_000_000_000) as u32;
                            chrono::DateTime::from_timestamp(secs, nanos)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
                        };

                        let operation = match event.operation {
                            infera_types::ChangeOperation::Create => "create",
                            infera_types::ChangeOperation::Delete => "delete",
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

                        last_revision = event.revision.next();

                        let result = Event::default()
                            .event("change")
                            .json_data(data);

                        yield result;
                    }

                    // If no events, wait a bit before polling again
                    if events.is_empty() {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
                Err(e) => {
                    let error_data = serde_json::json!({
                        "error": format!("Failed to read changes: {}", e)
                    });

                    let result = Event::default()
                        .event("error")
                        .json_data(error_data);

                    yield result;
                    break;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
