//! Internal API handlers for metrics
//!
//! The metrics endpoint is publicly accessible for Prometheus scraping.
//!
//! Note: HTTP cache invalidation endpoints have been removed.
//! Cache invalidation is now handled via Ledger-based WatchBlocks streaming.
//! See ledger_invalidation_watcher.rs for the implementation.

use axum::{http::StatusCode, response::IntoResponse};

/// Prometheus metrics endpoint
///
/// Returns all server metrics in Prometheus text format.
/// This endpoint does NOT require authentication and is intended
/// for Prometheus scraping.
///
/// # Returns
///
/// 200 OK with metrics in Prometheus text format, or
/// 503 SERVICE UNAVAILABLE if metrics haven't been initialized
pub async fn metrics_handler() -> impl IntoResponse {
    match inferadb_engine_observe::render_metrics() {
        Some(metrics) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
            metrics,
        )
            .into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "Metrics not initialized").into_response(),
    }
}
