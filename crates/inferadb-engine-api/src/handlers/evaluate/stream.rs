//! Streaming evaluation handler using Server-Sent Events
//!
//! This is a thin protocol adapter that converts REST requests to service calls.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt};
use inferadb_engine_const::scopes::*;
use inferadb_engine_core::DecisionTrace;
use inferadb_engine_types::{Decision, EvaluateRequest};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Result,
    content_negotiation::{AcceptHeader, ResponseFormat},
    handlers::utils::auth::authorize_request,
};

/// Request for batch authorization evaluation (streaming endpoint)
#[derive(Serialize, Deserialize, Debug)]
pub struct EvaluateRestRequest {
    /// Array of evaluate requests to process
    pub evaluations: Vec<EvaluateRequest>,
}

/// Response for a single evaluation in the batch
#[derive(Serialize, Deserialize, Debug)]
pub struct EvaluateRestResponse {
    /// Decision (allow or deny)
    pub decision: String,
    /// Index of the request this response corresponds to
    pub index: u32,
    /// Error message if evaluation failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional detailed evaluation trace (included when trace was set in request)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<DecisionTrace>,
}

/// Summary event sent at the end of the stream
#[derive(Serialize, Deserialize, Debug)]
pub struct EvaluateSummary {
    /// Total number of evaluations processed
    pub total: u32,
    /// Whether the stream completed successfully
    pub complete: bool,
}

/// Streaming authorization evaluation endpoint using Server-Sent Events
///
/// Supports both single evaluations (array of 1) and batch evaluations (array of N).
/// Returns decisions as they're evaluated, enabling progressive rendering
/// for large batches.
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.check` scope
///
/// # Request Body
/// ```json
/// {
///   "evaluations": [
///     {
///       "subject": "user:alice",
///       "resource": "document:report",
///       "permission": "view",
///       "trace": false
///     }
///   ]
/// }
/// ```
///
/// # Response (Server-Sent Events)
/// Stream of evaluation results followed by a summary:
/// ```text
/// data: {"decision":"allow","index":0,"error":null,"trace":null}
///
/// event: summary
/// data: {"total":1,"complete":true}
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing `inferadb.check` scope or vault access denied
/// - 400 Bad Request: Empty evaluations array or invalid request format
#[tracing::instrument(skip(state))]
pub async fn evaluate_stream_handler(
    auth: inferadb_engine_auth::extractor::OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
    Json(request): Json<EvaluateRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // Streaming endpoints only support JSON (SSE with JSON payloads)
    if format == ResponseFormat::Toon {
        return Err(ApiError::InvalidRequest(
            "Streaming endpoints do not support TOON format. Use Accept: application/json or text/event-stream".to_string()
        ));
    }

    // Authorize request and extract vault
    let vault = authorize_request(&auth.0, &[SCOPE_CHECK])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            "Streaming check request from tenant: {} (vault: {})",
            auth_ctx.organization,
            vault
        );
    }

    // Validate request
    if request.evaluations.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one evaluation must be provided".to_string(),
        ));
    }

    let evaluations = request.evaluations;
    let total_evaluations = evaluations.len() as u32;

    // Get evaluation service
    let evaluation_service = Arc::clone(&state.evaluation_service);

    // Create a stream that processes each evaluation and emits results
    let stream = futures::stream::iter(evaluations.into_iter().enumerate())
        .then(move |(index, evaluate_request)| {
            let evaluation_service = evaluation_service.clone();
            async move {
                // Check if trace is requested
                let trace = evaluate_request.trace.unwrap_or(false);

                if trace {
                    // Perform evaluation with trace using service (handles validation)
                    match evaluation_service.evaluate_with_trace(vault, evaluate_request).await {
                        Ok(trace_result) => Event::default().json_data(EvaluateRestResponse {
                            decision: match trace_result.decision {
                                Decision::Allow => "allow".to_string(),
                                Decision::Deny => "deny".to_string(),
                            },
                            index: index as u32,
                            error: None,
                            trace: Some(trace_result),
                        }),
                        Err(e) => Event::default().json_data(EvaluateRestResponse {
                            decision: "deny".to_string(),
                            index: index as u32,
                            error: Some(e.to_string()),
                            trace: None,
                        }),
                    }
                } else {
                    // Perform regular evaluation without trace using service (handles validation)
                    match evaluation_service.evaluate(vault, evaluate_request).await {
                        Ok(decision) => Event::default().json_data(EvaluateRestResponse {
                            decision: match decision {
                                Decision::Allow => "allow".to_string(),
                                Decision::Deny => "deny".to_string(),
                            },
                            index: index as u32,
                            error: None,
                            trace: None,
                        }),
                        Err(e) => Event::default().json_data(EvaluateRestResponse {
                            decision: "deny".to_string(),
                            index: index as u32,
                            error: Some(e.to_string()),
                            trace: None,
                        }),
                    }
                }
            }
        })
        .chain(futures::stream::once(async move {
            // Send summary event at the end
            Event::default()
                .event("summary")
                .json_data(EvaluateSummary { total: total_evaluations, complete: true })
        }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
