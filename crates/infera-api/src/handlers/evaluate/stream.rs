//! Streaming evaluation handler using Server-Sent Events

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt};
use infera_const::scopes::*;
use infera_core::{DecisionTrace, Evaluator};
use infera_store::RelationshipStore;
use infera_types::{Decision, EvaluateRequest};
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState, Result, handlers::utils::auth::authorize_request};

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
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<EvaluateRestRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // Authorize request and extract vault
    let vault =
        authorize_request(&auth.0, state.default_vault, state.config.auth.enabled, &[SCOPE_CHECK])?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            "Streaming check request from tenant: {} (vault: {})",
            auth_ctx.tenant_id,
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

    // Create evaluator with correct vault for this request
    let evaluator = Arc::new(Evaluator::new(
        Arc::clone(&state.store) as Arc<dyn RelationshipStore>,
        Arc::clone(state.evaluator.schema()),
        state.evaluator.wasm_host().cloned(),
        vault,
    ));

    // Create a stream that processes each evaluation and emits results
    let stream = futures::stream::iter(evaluations.into_iter().enumerate())
        .then(move |(index, evaluate_request)| {
            let evaluator = evaluator.clone();
            async move {
                // Validate individual evaluation
                if evaluate_request.subject.is_empty() {
                    return Event::default().json_data(EvaluateRestResponse {
                        decision: "deny".to_string(),
                        index: index as u32,
                        error: Some("Subject cannot be empty".to_string()),
                        trace: None,
                    });
                }
                if evaluate_request.resource.is_empty() {
                    return Event::default().json_data(EvaluateRestResponse {
                        decision: "deny".to_string(),
                        index: index as u32,
                        error: Some("Resource cannot be empty".to_string()),
                        trace: None,
                    });
                }
                if evaluate_request.permission.is_empty() {
                    return Event::default().json_data(EvaluateRestResponse {
                        decision: "deny".to_string(),
                        index: index as u32,
                        error: Some("Permission cannot be empty".to_string()),
                        trace: None,
                    });
                }

                // Check if trace is requested
                let trace = evaluate_request.trace.unwrap_or(false);

                if trace {
                    // Perform evaluation with trace
                    match evaluator.check_with_trace(evaluate_request).await {
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
                            error: Some(format!("Evaluation error: {}", e)),
                            trace: None,
                        }),
                    }
                } else {
                    // Perform regular evaluation without trace
                    match evaluator.check(evaluate_request).await {
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
                            error: Some(format!("Evaluation error: {}", e)),
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
