//! Axum extractors for authentication
//!
//! This module provides convenient extractors for accessing authentication
//! context in Axum handlers:
//!
//! - `RequireAuth`: Requires authentication, returns 401 if not present
//! - `OptionalAuth`: Optional authentication, returns None if not present

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use infera_types::AuthContext;

/// Extractor that requires authentication
///
/// This extractor will return a 401 Unauthorized error if the AuthContext
/// is not present in the request extensions (i.e., if the auth middleware
/// didn't run or authentication failed).
///
/// # Example
///
/// ```rust,no_run
/// use axum::{Json, response::Result};
/// use infera_auth::extractor::RequireAuth;
/// use serde_json::Value;
///
/// async fn protected_handler(
///     RequireAuth(auth): RequireAuth,
///     Json(payload): Json<Value>,
/// ) -> Result<Json<Value>> {
///     // auth is guaranteed to be present here
///     println!("Authenticated as tenant: {}", auth.tenant_id);
///     Ok(Json(payload))
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RequireAuth(pub AuthContext);

impl<S> FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<AuthContext>().cloned().map(RequireAuth).ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Authentication required but not present").into_response()
        })
    }
}

/// Extractor for optional authentication
///
/// This extractor returns `Some(AuthContext)` if authentication is present,
/// or `None` if not. It never fails, making it useful for endpoints that
/// can work with or without authentication.
///
/// # Example
///
/// ```rust,no_run
/// use axum::{Json, response::Result};
/// use infera_auth::extractor::OptionalAuth;
/// use serde_json::Value;
///
/// async fn flexible_handler(
///     OptionalAuth(auth): OptionalAuth,
///     Json(payload): Json<Value>,
/// ) -> Result<Json<Value>> {
///     if let Some(auth) = auth {
///         println!("Authenticated as tenant: {}", auth.tenant_id);
///     } else {
///         println!("Unauthenticated request");
///     }
///     Ok(Json(payload))
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<AuthContext>);

impl<S> FromRequestParts<S> for OptionalAuth
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts.extensions.get::<AuthContext>().cloned();
        Ok(OptionalAuth(auth))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{Request, StatusCode};
    use chrono::{Duration, Utc};
    use infera_types::AuthMethod;

    use super::*;

    fn create_test_auth_context() -> AuthContext {
        AuthContext {
            tenant_id: "test-tenant".to_string(),
            client_id: "test-client".to_string(),
            key_id: "test-key-001".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: vec!["inferadb.check".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            jti: Some("test-jti".to_string()),
            vault: uuid::Uuid::nil(),
            account: uuid::Uuid::nil(),
        }
    }

    #[tokio::test]
    async fn test_require_auth_with_context() {
        let auth = create_test_auth_context();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(auth.clone());

        let (mut parts, _) = req.into_parts();
        let result = RequireAuth::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let RequireAuth(extracted_auth) = result.unwrap();
        assert_eq!(extracted_auth.tenant_id, "test-tenant");
    }

    #[tokio::test]
    async fn test_require_auth_without_context() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        let result = RequireAuth::from_request_parts(&mut parts, &()).await;

        assert!(result.is_err());
        let response = result.unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_optional_auth_with_context() {
        let auth = create_test_auth_context();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(auth.clone());

        let (mut parts, _) = req.into_parts();
        let result = OptionalAuth::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let OptionalAuth(extracted_auth) = result.unwrap();
        assert!(extracted_auth.is_some());
        assert_eq!(extracted_auth.unwrap().tenant_id, "test-tenant");
    }

    #[tokio::test]
    async fn test_optional_auth_without_context() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        let result = OptionalAuth::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let OptionalAuth(extracted_auth) = result.unwrap();
        assert!(extracted_auth.is_none());
    }
}
