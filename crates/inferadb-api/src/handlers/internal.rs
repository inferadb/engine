//! Internal API handlers for cache management and metrics
//!
//! These handlers are called by the Management API to invalidate server-side caches
//! when vaults or organizations are updated. They are protected by Management JWT authentication.
//! The metrics endpoint is publicly accessible for Prometheus scraping.

use std::sync::Arc;

use axum::{Extension, extract::Path, http::StatusCode, response::IntoResponse};
use inferadb_auth::{CertificateCache, ManagementApiVaultVerifier};

/// Invalidate vault cache for a specific vault
///
/// Called by Management API when a vault is updated or deleted.
///
/// # Arguments
///
/// * `Path(vault_id)` - The Snowflake ID of the vault to invalidate
/// * `Extension(verifier)` - The vault verifier containing the cache
///
/// # Returns
///
/// 204 NO CONTENT on success
///
/// # Security
///
/// This endpoint MUST be protected by Management JWT authentication middleware.
/// Only the Management API should be able to call this endpoint.
pub async fn invalidate_vault_cache(
    Path(vault_id): Path<i64>,
    Extension(verifier): Extension<Arc<ManagementApiVaultVerifier>>,
) -> impl IntoResponse {
    tracing::info!(
        vault_id = %vault_id,
        event_type = "internal.cache_invalidation",
        "Received vault cache invalidation request from Management API"
    );

    verifier.invalidate_vault(vault_id).await;

    StatusCode::NO_CONTENT
}

/// Invalidate organization cache for a specific organization
///
/// Called by Management API when an organization is updated or suspended.
///
/// # Arguments
///
/// * `Path(org_id)` - The Snowflake ID of the organization to invalidate
/// * `Extension(verifier)` - The vault verifier containing the cache
///
/// # Returns
///
/// 204 NO CONTENT on success
///
/// # Security
///
/// This endpoint MUST be protected by Management JWT authentication middleware.
/// Only the Management API should be able to call this endpoint.
pub async fn invalidate_organization_cache(
    Path(org_id): Path<i64>,
    Extension(verifier): Extension<Arc<ManagementApiVaultVerifier>>,
) -> impl IntoResponse {
    tracing::info!(
        org_id = %org_id,
        event_type = "internal.cache_invalidation",
        "Received organization cache invalidation request from Management API"
    );

    verifier.invalidate_organization(org_id).await;

    StatusCode::NO_CONTENT
}

/// Clear all caches (nuclear option)
///
/// Called by Management API for emergency cache clearing or after major changes.
/// This will cause a temporary spike in management API requests as caches are rebuilt.
///
/// # Arguments
///
/// * `Extension(verifier)` - The vault verifier containing the caches
///
/// # Returns
///
/// 204 NO CONTENT on success
///
/// # Security
///
/// This endpoint MUST be protected by Management JWT authentication middleware.
/// Only the Management API should be able to call this endpoint.
pub async fn clear_all_caches(
    Extension(verifier): Extension<Arc<ManagementApiVaultVerifier>>,
) -> impl IntoResponse {
    tracing::warn!(
        event_type = "internal.cache_invalidation",
        "Received clear all caches request from Management API"
    );

    verifier.clear_all_caches().await;

    StatusCode::NO_CONTENT
}

/// Invalidate certificate cache for a specific certificate
///
/// Called by Management API when a certificate is revoked or deleted.
///
/// # Arguments
///
/// * `Path((org_id, client_id, cert_id))` - The IDs identifying the certificate to invalidate
/// * `Extension(cert_cache)` - The certificate cache
///
/// # Returns
///
/// 204 NO CONTENT on success
///
/// # Security
///
/// This endpoint MUST be protected by Management JWT authentication middleware.
/// Only the Management API should be able to call this endpoint.
pub async fn invalidate_certificate_cache(
    Path((org_id, client_id, cert_id)): Path<(i64, i64, i64)>,
    Extension(cert_cache): Extension<Arc<CertificateCache>>,
) -> impl IntoResponse {
    tracing::info!(
        org_id = %org_id,
        client_id = %client_id,
        cert_id = %cert_id,
        event_type = "internal.cache_invalidation",
        "Received certificate cache invalidation request from Management API"
    );

    cert_cache.invalidate(org_id, client_id, cert_id).await;

    StatusCode::NO_CONTENT
}

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
    match inferadb_observe::render_metrics() {
        Some(metrics) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
            metrics,
        )
            .into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "Metrics not initialized").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{body::Body, http::Request};
    use inferadb_auth::ManagementClient;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn test_invalidate_vault_cache_handler() {
        // Create a test vault verifier
        let client = Arc::new(
            ManagementClient::new("http://localhost:8081".to_string(), None, 5000, None, None)
                .unwrap(),
        );
        let verifier = Arc::new(ManagementApiVaultVerifier::new(
            client,
            Duration::from_secs(300),
            Duration::from_secs(600),
        ));

        // Create a simple router for testing
        let app = axum::Router::new()
            .route(
                "/internal/cache/invalidate/vault/{vault_id}",
                axum::routing::post(invalidate_vault_cache),
            )
            .layer(Extension(verifier));

        // Make request
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/cache/invalidate/vault/123456789")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_invalidate_organization_cache_handler() {
        let client = Arc::new(
            ManagementClient::new("http://localhost:8081".to_string(), None, 5000, None, None)
                .unwrap(),
        );
        let verifier = Arc::new(ManagementApiVaultVerifier::new(
            client,
            Duration::from_secs(300),
            Duration::from_secs(600),
        ));

        let app = axum::Router::new()
            .route(
                "/internal/cache/invalidate/organization/{org_id}",
                axum::routing::post(invalidate_organization_cache),
            )
            .layer(Extension(verifier));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/cache/invalidate/organization/987654321")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_clear_all_caches_handler() {
        let client = Arc::new(
            ManagementClient::new("http://localhost:8081".to_string(), None, 5000, None, None)
                .unwrap(),
        );
        let verifier = Arc::new(ManagementApiVaultVerifier::new(
            client,
            Duration::from_secs(300),
            Duration::from_secs(600),
        ));

        let app = axum::Router::new()
            .route("/internal/cache/invalidate/all", axum::routing::post(clear_all_caches))
            .layer(Extension(verifier));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/cache/invalidate/all")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
