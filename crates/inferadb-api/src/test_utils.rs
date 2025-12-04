//! Test utilities for handler tests
//!
//! This module provides common utilities for testing handlers that require
//! authentication. Since authentication is always enabled, tests need to inject
//! test auth context using the provided middleware.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use infera_types::{AuthContext, AuthMethod};

/// Create a default test auth context with admin permissions
pub fn create_test_auth_context(vault: i64, organization: i64) -> AuthContext {
    AuthContext {
        client_id: "test_client".to_string(),
        key_id: "test_key".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes: vec![
            "inferadb.admin".to_string(),
            "inferadb.check".to_string(),
            "inferadb.write".to_string(),
            "inferadb.expand".to_string(),
            "inferadb.list".to_string(),
            "inferadb.list_subjects".to_string(),
            "inferadb.list_resources".to_string(),
            "inferadb.list_relationships".to_string(),
        ],
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        jti: Some("test_jti".to_string()),
        vault,
        organization,
    }
}

/// Test middleware that injects an AuthContext into request extensions
pub async fn test_auth_middleware(
    auth_context: AuthContext,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    request.extensions_mut().insert(Arc::new(auth_context));
    next.run(request).await
}

/// Wrap a router with test authentication
///
/// Use this to wrap handlers that require authentication in tests.
///
/// # Example
///
/// ```ignore
/// let app = Router::new()
///     .route("/v1/check", post(check_handler))
///     .with_state(state.clone());
/// let app = with_test_auth(app, state.default_vault, state.default_organization);
/// ```
pub fn with_test_auth(router: Router, vault: i64, organization: i64) -> Router {
    let auth = create_test_auth_context(vault, organization);
    router.layer(middleware::from_fn(move |req, next| {
        let auth_clone = auth.clone();
        async move { test_auth_middleware(auth_clone, req, next).await }
    }))
}

/// Create test auth context with custom scopes
pub fn create_test_auth_with_scopes(
    vault: i64,
    organization: i64,
    scopes: Vec<String>,
) -> AuthContext {
    AuthContext {
        client_id: "test_client".to_string(),
        key_id: "test_key".to_string(),
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes,
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        jti: Some("test_jti".to_string()),
        vault,
        organization,
    }
}

/// Wrap a router with test authentication using custom auth context
pub fn with_custom_test_auth(router: Router, auth_context: AuthContext) -> Router {
    router.layer(middleware::from_fn(move |req, next| {
        let auth_clone = auth_context.clone();
        async move { test_auth_middleware(auth_clone, req, next).await }
    }))
}
