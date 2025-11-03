//! Expand endpoint - streaming-only for progressive results

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt, stream};
use infera_const::scopes::*;
use infera_core::Evaluator;
use infera_store::RelationshipStore;
use infera_types::ExpandRequest;

use crate::{AppState, Result, handlers::utils::auth::authorize_request};

/// Expand endpoint - streaming-only for progressive results
///
/// Returns users as they're discovered, enabling progressive rendering
/// for large result sets.
#[tracing::instrument(skip(state))]
pub async fn expand_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<ExpandRequest>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    // Authorize request and extract vault
    let vault = authorize_request(
        &auth.0,
        state.default_vault,
        state.config.auth.enabled,
        &[SCOPE_EXPAND, SCOPE_CHECK],
    )?;

    // Log authenticated requests
    if let Some(ref auth_ctx) = auth.0 {
        tracing::debug!(
            "Streaming expand request from tenant: {} (vault: {})",
            auth_ctx.tenant_id,
            vault
        );
    }

    // Create evaluator with correct vault for this request
    let evaluator = Evaluator::new(
        Arc::clone(&state.store) as Arc<dyn RelationshipStore>,
        Arc::clone(state.evaluator.schema()),
        state.evaluator.wasm_host().cloned(),
        vault,
    );

    // Execute the expand operation
    let response = evaluator.expand(request).await?;

    // Create a stream that sends each user as a separate SSE event
    let users = response.users;
    let tree = response.tree;
    let continuation_token = response.continuation_token;
    let total_count = response.total_count;

    let stream = stream::iter(users.into_iter().enumerate().map(|(idx, user)| {
        let data = serde_json::json!({
            "subject": user,
            "index": idx,
        });

        Event::default().json_data(data)
    }))
    .chain(stream::once(async move {
        // Send final summary event
        let summary = serde_json::json!({
            "tree": tree,
            "continuation_token": continuation_token,
            "total_count": total_count,
            "complete": true
        });

        Event::default().event("summary").json_data(summary)
    }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
