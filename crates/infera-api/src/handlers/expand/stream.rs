//! Expand endpoint - streaming-only for progressive results

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt, stream};
use infera_core::Evaluator;
use infera_store::RelationshipStore;
use infera_types::ExpandRequest;

use crate::{ApiError, AppState, Result, handlers::utils::auth::get_vault};

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
    // Extract vault from auth context or use default
    let vault = get_vault(&auth.0, state.default_vault);

    // Validate vault access (basic nil check)
    if let Some(ref auth_ctx) = auth.0 {
        infera_auth::validate_vault_access(auth_ctx)
            .map_err(|e| ApiError::Forbidden(format!("Vault access denied: {}", e)))?;
    }

    // If auth is enabled and present, validate scope
    if state.config.auth.enabled {
        if let Some(ref auth_ctx) = auth.0 {
            // Require inferadb.expand scope (or check scope as fallback)
            infera_auth::middleware::require_any_scope(
                auth_ctx,
                &["inferadb.expand", "inferadb.check"],
            )
            .map_err(|e| ApiError::Forbidden(e.to_string()))?;

            tracing::debug!(
                "Streaming expand request from tenant: {} (vault: {})",
                auth_ctx.tenant_id,
                vault
            );
        } else {
            return Err(ApiError::Unauthorized("Authentication required".to_string()));
        }
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
