//! Axum middleware for JWT authentication
//!
//! This module provides authentication middleware that:
//! - Extracts bearer tokens from HTTP Authorization headers
//! - Validates JWT signatures using JWKS
//! - Creates authenticated request contexts
//! - Enforces scope-based authorization

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use infera_types::{AuthContext, AuthMethod};

use crate::{error::AuthError, jwks_cache::JwksCache, jwt::verify_with_jwks, metrics::AuthMetrics};

/// Helper to create unauthorized response with WWW-Authenticate header
fn unauthorized_response(message: &str) -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, message.to_string()).into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"InferaDB\", error=\"invalid_token\""),
    );
    response
}

/// Extract bearer token from Authorization header
///
/// Expects header format: `Authorization: Bearer <token>`
///
/// # Arguments
///
/// * `headers` - The HTTP request headers
///
/// # Returns
///
/// Returns the token string if present and well-formed
///
/// # Errors
///
/// Returns `AuthError::Unauthorized` if:
/// - The Authorization header is missing
/// - The header doesn't start with "Bearer "
/// - The token part is empty
///
/// # Example
///
/// ```
/// use axum::http::HeaderMap;
/// use infera_auth::middleware::extract_bearer_token;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("authorization", "Bearer eyJ0eXAi...".parse().unwrap());
///
/// let token = extract_bearer_token(&headers).unwrap();
/// assert!(token.starts_with("eyJ"));
/// ```
pub fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AuthError> {
    // Get Authorization header
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AuthError::InvalidTokenFormat("Missing Authorization header".into()))?;

    // Convert to string
    let auth_str = auth_header.to_str().map_err(|_| {
        AuthError::InvalidTokenFormat("Invalid Authorization header encoding".into())
    })?;

    // Check for "Bearer " prefix (case-insensitive)
    if !auth_str.starts_with("Bearer ") && !auth_str.starts_with("bearer ") {
        return Err(AuthError::InvalidTokenFormat(
            "Authorization header must use Bearer scheme".into(),
        ));
    }

    // Extract token part after "Bearer "
    let token = auth_str[7..].trim();

    // Ensure token is not empty
    if token.is_empty() {
        return Err(AuthError::InvalidTokenFormat("Bearer token is empty".into()));
    }

    Ok(token.to_string())
}

/// Require a specific scope to be present in the auth context
///
/// # Arguments
///
/// * `auth` - The authenticated context
/// * `scope` - The required scope (e.g., "inferadb.check")
///
/// # Errors
///
/// Returns `AuthError::InvalidScope` if the scope is not present
pub fn require_scope(auth: &AuthContext, scope: &str) -> Result<(), AuthError> {
    if !auth.has_scope(scope) {
        return Err(AuthError::InvalidScope(format!("Required scope '{}' not present", scope)));
    }
    Ok(())
}

/// Require any one of the specified scopes to be present
///
/// # Arguments
///
/// * `auth` - The authenticated context
/// * `scopes` - List of acceptable scopes
///
/// # Errors
///
/// Returns `AuthError::InvalidScope` if none of the scopes are present
pub fn require_any_scope(auth: &AuthContext, scopes: &[&str]) -> Result<(), AuthError> {
    for scope in scopes {
        if auth.has_scope(scope) {
            return Ok(());
        }
    }

    Err(AuthError::InvalidScope(format!("Required one of scopes: {}", scopes.join(", "))))
}

/// Axum middleware for JWT authentication
///
/// This middleware:
/// 1. Extracts the bearer token from the Authorization header
/// 2. Decodes and verifies the JWT using JWKS
/// 3. Creates an AuthContext from the validated claims
/// 4. Injects the context into request extensions
///
/// # Arguments
///
/// * `jwks_cache` - The JWKS cache for verifying signatures
/// * `request` - The incoming HTTP request
/// * `next` - The next layer in the middleware stack
///
/// # Returns
///
/// Returns the response from the next layer, or an error response if authentication fails
///
/// # Errors
///
/// Returns appropriate HTTP status codes:
/// - 401 Unauthorized: Missing or invalid token, expired token
/// - 403 Forbidden: Invalid scope, audience mismatch
/// - 500 Internal Server Error: JWKS fetch or verification errors
pub async fn auth_middleware(
    jwks_cache: Arc<JwksCache>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    auth_middleware_impl(jwks_cache, None, request, next).await
}

/// Axum middleware for JWT authentication with metrics
///
/// This middleware:
/// 1. Extracts the bearer token from the Authorization header
/// 2. Decodes and verifies the JWT using JWKS
/// 3. Creates an AuthContext from the validated claims
/// 4. Injects the context into request extensions
/// 5. Records validation success/failure and duration metrics
///
/// # Arguments
///
/// * `jwks_cache` - The JWKS cache for verifying signatures
/// * `metrics` - Prometheus metrics collector
/// * `request` - The incoming HTTP request
/// * `next` - The next layer in the middleware stack
///
/// # Returns
///
/// Returns the response from the next layer, or an error response if authentication fails
pub async fn auth_middleware_with_metrics(
    jwks_cache: Arc<JwksCache>,
    metrics: Arc<AuthMetrics>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    auth_middleware_impl(jwks_cache, Some(metrics), request, next).await
}

/// Internal implementation of auth middleware with optional metrics
async fn auth_middleware_impl(
    jwks_cache: Arc<JwksCache>,
    metrics: Option<Arc<AuthMetrics>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Start timing if metrics are enabled
    let _timer = metrics.as_ref().map(|m| m.start_validation_timer("jwt"));

    // Extract bearer token from headers
    let token = extract_bearer_token(request.headers()).map_err(|e| {
        if let Some(ref m) = metrics {
            m.record_validation_failure("jwt");
        }
        unauthorized_response(&e.to_string())
    })?;

    // Verify JWT with JWKS and get validated claims
    let claims = verify_with_jwks(&token, &jwks_cache).await.map_err(|e| {
        if let Some(ref m) = metrics {
            m.record_validation_failure("jwt");
        }
        match e {
            AuthError::TokenExpired => unauthorized_response("Token expired"),
            AuthError::TokenNotYetValid => unauthorized_response("Token not yet valid"),
            AuthError::InvalidSignature => unauthorized_response("Invalid signature"),
            AuthError::InvalidTokenFormat(ref msg) => unauthorized_response(msg),
            AuthError::InvalidAudience(msg) => {
                (StatusCode::FORBIDDEN, format!("Invalid audience: {}", msg)).into_response()
            },
            AuthError::InvalidScope(msg) => {
                (StatusCode::FORBIDDEN, format!("Invalid scope: {}", msg)).into_response()
            },
            _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    })?;

    // Extract tenant ID from claims
    let tenant_id = claims.extract_tenant_id().map_err(|e| {
        if let Some(ref m) = metrics {
            m.record_validation_failure("jwt");
        }
        (StatusCode::UNAUTHORIZED, e.to_string()).into_response()
    })?;

    // Extract vault and account UUIDs from claims
    let vault_str = claims.extract_vault().ok_or_else(|| {
        if let Some(ref m) = metrics {
            m.record_validation_failure("jwt");
        }
        (StatusCode::UNAUTHORIZED, "Missing vault claim in JWT".to_string()).into_response()
    })?;
    let vault = uuid::Uuid::parse_str(&vault_str).map_err(|_| {
        if let Some(ref m) = metrics {
            m.record_validation_failure("jwt");
        }
        (StatusCode::UNAUTHORIZED, "Invalid vault UUID format".to_string()).into_response()
    })?;

    let account_str = claims.extract_account().ok_or_else(|| {
        if let Some(ref m) = metrics {
            m.record_validation_failure("jwt");
        }
        (StatusCode::UNAUTHORIZED, "Missing account claim in JWT".to_string()).into_response()
    })?;
    let account = uuid::Uuid::parse_str(&account_str).map_err(|_| {
        if let Some(ref m) = metrics {
            m.record_validation_failure("jwt");
        }
        (StatusCode::UNAUTHORIZED, "Invalid account UUID format".to_string()).into_response()
    })?;

    // Parse scopes from space-separated string
    let scopes: Vec<String> = claims.scope.split_whitespace().map(|s| s.to_string()).collect();

    // Create AuthContext
    let auth_context = AuthContext {
        tenant_id,
        client_id: claims.sub.clone(),
        key_id: String::new(), // Will be populated from JWT header kid in next iteration
        auth_method: AuthMethod::PrivateKeyJwt,
        scopes,
        issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
            .unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(300)),
        jti: claims.jti.clone(),
        vault,
        account,
    };

    // Record successful validation
    if let Some(ref m) = metrics {
        m.record_validation_success("jwt");
    }

    // Insert AuthContext into request extensions
    request.extensions_mut().insert(auth_context);

    // Continue to next middleware/handler
    Ok(next.run(request).await)
}

/// Validate vault access in AuthContext (basic validation only)
///
/// This function performs basic vault-level access validation:
/// 1. Ensures vault UUID is not nil
/// 2. Logs vault access for audit purposes
///
/// For full validation including database checks, use
/// `infera_api::vault_validation::validate_vault_access_with_store`.
///
/// # Arguments
///
/// * `auth` - The authenticated context containing vault information
///
/// # Errors
///
/// Returns `AuthError::InvalidTokenFormat` if:
/// - Vault UUID is nil (indicates missing/invalid vault claim)
pub fn validate_vault_access(auth: &AuthContext) -> Result<(), AuthError> {
    // Check if vault is nil UUID
    if auth.vault.is_nil() {
        tracing::warn!(
            tenant_id = %auth.tenant_id,
            client_id = %auth.client_id,
            "Vault access denied: nil UUID detected"
        );
        return Err(AuthError::InvalidTokenFormat(
            "Invalid vault: vault UUID cannot be nil".to_string(),
        ));
    }

    // Log vault access for audit trail
    tracing::debug!(
        tenant_id = %auth.tenant_id,
        vault = %auth.vault,
        account = %auth.account,
        client_id = %auth.client_id,
        "Vault access validated (basic)"
    );

    Ok(())
}

/// Axum middleware for vault access validation
///
/// This middleware layer validates that the authenticated request has proper
/// vault access. It should be applied after auth_middleware in the middleware stack.
///
/// # Arguments
///
/// * `request` - The incoming HTTP request (must have AuthContext in extensions)
/// * `next` - The next layer in the middleware stack
///
/// # Returns
///
/// Returns the response from the next layer, or an error response if vault validation fails
///
/// # Errors
///
/// Returns HTTP 403 Forbidden if vault validation fails
///
/// # Example
///
/// ```ignore
/// use axum::{Router, middleware};
/// use infera_auth::middleware::{auth_middleware, vault_validation_middleware};
///
/// let app = Router::new()
///     .route("/api/check", post(check_handler))
///     .layer(middleware::from_fn(vault_validation_middleware))
///     .layer(middleware::from_fn(move |req, next| {
///         auth_middleware(jwks_cache.clone(), req, next)
///     }));
/// ```
pub async fn vault_validation_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Extract AuthContext from request extensions
    let auth = request.extensions().get::<AuthContext>().cloned().ok_or_else(|| {
        tracing::error!("AuthContext missing from request extensions");
        (StatusCode::INTERNAL_SERVER_ERROR, "Authentication context not found".to_string())
            .into_response()
    })?;

    // Validate vault access
    validate_vault_access(&auth).map_err(|e| {
        tracing::warn!(
            error = %e,
            vault = %auth.vault,
            tenant_id = %auth.tenant_id,
            "Vault validation failed"
        );
        (StatusCode::FORBIDDEN, format!("Vault access denied: {}", e)).into_response()
    })?;

    // Vault validation passed, continue to handler
    Ok(next.run(request).await)
}

/// Optional authentication middleware that respects auth.enabled config
///
/// When auth is disabled (auth.enabled = false), this middleware:
/// - Logs a warning that authentication is disabled
/// - Injects a default AuthContext with the provided vault/account
/// - Passes the request through without token validation
///
/// When auth is enabled, delegates to the standard auth_middleware.
///
/// # Arguments
///
/// * `enabled` - Whether authentication is enabled
/// * `default_vault` - Default vault UUID to use when auth is disabled
/// * `default_account` - Default account UUID to use when auth is disabled
/// * `jwks_cache` - The JWKS cache for verifying signatures (only used if enabled)
/// * `request` - The incoming HTTP request
/// * `next` - The next layer in the middleware stack
///
/// # Returns
///
/// Returns the response from the next layer
///
/// # Security Warning
///
/// Only use this middleware in development/testing environments.
/// Production systems should always have authentication enabled.
pub async fn optional_auth_middleware(
    enabled: bool,
    default_vault: uuid::Uuid,
    default_account: uuid::Uuid,
    jwks_cache: Arc<JwksCache>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    if !enabled {
        tracing::warn!(
            "Authentication is DISABLED - using default vault {} and account {}",
            default_vault,
            default_account
        );

        // Create default AuthContext for unauthenticated requests
        let auth_context = AuthContext::default_unauthenticated(default_vault, default_account);
        request.extensions_mut().insert(auth_context);

        return Ok(next.run(request).await);
    }

    // Auth is enabled, delegate to standard middleware
    auth_middleware(jwks_cache, request, next).await
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use chrono::{Duration, Utc};

    use super::*;

    fn create_test_auth_context(scopes: Vec<&str>) -> AuthContext {
        AuthContext {
            tenant_id: "test".to_string(),
            client_id: "test-client".to_string(),
            key_id: "test-key-001".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: scopes.into_iter().map(|s| s.to_string()).collect(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            jti: Some("test-jti".to_string()),
            vault: uuid::Uuid::nil(),
            account: uuid::Uuid::nil(),
        }
    }

    #[test]
    fn test_extract_bearer_token_success() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token-123".parse().unwrap());

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "test-token-123");
    }

    #[test]
    fn test_extract_bearer_token_with_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer   token-with-spaces  ".parse().unwrap());

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "token-with-spaces");
    }

    #[test]
    fn test_extract_bearer_token_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "bearer lowercase-token".parse().unwrap());

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "lowercase-token");
    }

    #[test]
    fn test_extract_bearer_token_missing_header() {
        let headers = HeaderMap::new();

        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidTokenFormat(msg)) => assert!(msg.contains("Missing")),
            _ => panic!("Expected InvalidTokenFormat error"),
        }
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());

        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidTokenFormat(msg)) => assert!(msg.contains("Bearer")),
            _ => panic!("Expected InvalidTokenFormat error"),
        }
    }

    #[test]
    fn test_extract_bearer_token_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer   ".parse().unwrap());

        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidTokenFormat(msg)) => assert!(msg.contains("empty")),
            _ => panic!("Expected InvalidTokenFormat error"),
        }
    }

    #[test]
    fn test_require_scope_present() {
        let auth = create_test_auth_context(vec!["inferadb.check", "inferadb.write"]);

        assert!(require_scope(&auth, "inferadb.check").is_ok());
        assert!(require_scope(&auth, "inferadb.write").is_ok());
    }

    #[test]
    fn test_require_scope_missing() {
        let auth = create_test_auth_context(vec!["inferadb.check"]);

        let result = require_scope(&auth, "inferadb.write");
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidScope(msg)) => assert!(msg.contains("inferadb.write")),
            _ => panic!("Expected InvalidScope error"),
        }
    }

    #[test]
    fn test_require_any_scope_first_matches() {
        let auth = create_test_auth_context(vec!["inferadb.check"]);

        assert!(require_any_scope(&auth, &["inferadb.check", "inferadb.write"]).is_ok());
    }

    #[test]
    fn test_require_any_scope_second_matches() {
        let auth = create_test_auth_context(vec!["inferadb.write"]);

        assert!(require_any_scope(&auth, &["inferadb.check", "inferadb.write"]).is_ok());
    }

    #[test]
    fn test_require_any_scope_none_match() {
        let auth = create_test_auth_context(vec!["inferadb.read"]);

        let result = require_any_scope(&auth, &["inferadb.check", "inferadb.write"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_vault_access_valid() {
        let vault_id = uuid::Uuid::new_v4();
        let account_id = uuid::Uuid::new_v4();

        let auth = AuthContext {
            tenant_id: "test-tenant".to_string(),
            client_id: "test-client".to_string(),
            key_id: "test-key-001".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: vec!["inferadb.check".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            jti: Some("test-jti".to_string()),
            vault: vault_id,
            account: account_id,
        };

        assert!(validate_vault_access(&auth).is_ok());
    }

    #[test]
    fn test_validate_vault_access_nil_vault() {
        let auth = AuthContext {
            tenant_id: "test-tenant".to_string(),
            client_id: "test-client".to_string(),
            key_id: "test-key-001".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: vec!["inferadb.check".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            jti: Some("test-jti".to_string()),
            vault: uuid::Uuid::nil(),
            account: uuid::Uuid::new_v4(),
        };

        let result = validate_vault_access(&auth);
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidTokenFormat(msg)) => {
                assert!(msg.contains("vault") || msg.contains("nil"));
            },
            _ => panic!("Expected InvalidTokenFormat error"),
        }
    }

    #[test]
    fn test_validate_vault_access_with_default_vault() {
        // Test that non-nil vaults pass validation
        let default_vault = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let account_id = uuid::Uuid::new_v4();

        let auth = AuthContext {
            tenant_id: "default".to_string(),
            client_id: "system:unauthenticated".to_string(),
            key_id: "default".to_string(),
            auth_method: AuthMethod::InternalServiceJwt,
            scopes: vec!["inferadb.check".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            jti: None,
            vault: default_vault,
            account: account_id,
        };

        assert!(validate_vault_access(&auth).is_ok());
    }
}
