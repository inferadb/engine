//! gRPC Authentication Interceptor
//!
//! This module provides authentication for gRPC requests using Bearer tokens.
//! It supports:
//! - Tenant JWTs (from SDK/CLI)
//! - OAuth 2.0 access tokens
//! - Internal service JWTs
//!
//! ## Usage
//!
//! ```ignore
//! use tonic::transport::Server;
//! use crate::grpc_interceptor::AuthInterceptor;
//!
//! let interceptor = AuthInterceptor::new(jwks_cache, internal_loader, config);
//!
//! Server::builder()
//!     .add_service(InferaServiceServer::with_interceptor(service, interceptor))
//!     .serve(addr)
//!     .await?;
//! ```

use std::{sync::Arc, time::Instant};

// Re-export chrono from infera_auth's context module
use chrono::{DateTime, Duration, Utc};
use infera_auth::{
    audit::{AuditEvent, log_audit_event},
    context::{AuthContext, AuthMethod},
    error::AuthError,
    internal::InternalJwksLoader,
    jwks_cache::JwksCache,
    jwt, oauth,
};
use infera_config::AuthConfig;
use infera_observe::metrics;
use tonic::{Request, Status, metadata::MetadataMap};

/// Extract Bearer token from gRPC metadata
///
/// gRPC metadata keys are case-insensitive and normalized to lowercase.
/// This function looks for the "authorization" metadata entry.
///
/// # Errors
///
/// Returns error if:
/// - Authorization metadata is missing
/// - Authorization value is not valid UTF-8
/// - Authorization value doesn't start with "Bearer "
pub fn extract_bearer_from_metadata(metadata: &MetadataMap) -> Result<String, AuthError> {
    // CRITICAL: Always use lowercase "authorization" not "Authorization"
    // gRPC normalizes all metadata keys to lowercase
    let auth_value = metadata.get("authorization").ok_or_else(|| {
        AuthError::InvalidTokenFormat("Missing authorization metadata".to_string())
    })?;

    // Convert metadata value to string
    let auth_str = auth_value.to_str().map_err(|_| {
        AuthError::InvalidTokenFormat("Invalid authorization header encoding".to_string())
    })?;

    // Check for Bearer prefix
    if !auth_str.starts_with("Bearer ") {
        return Err(AuthError::InvalidTokenFormat(
            "Authorization header must start with 'Bearer '".to_string(),
        ));
    }

    // Extract token (skip "Bearer " prefix)
    let token = &auth_str[7..];
    if token.is_empty() {
        return Err(AuthError::InvalidTokenFormat("Empty bearer token".to_string()));
    }

    Ok(token.to_string())
}

/// gRPC Authentication Interceptor
///
/// This interceptor:
/// 1. Extracts the Bearer token from authorization metadata
/// 2. Determines the token type (JWT vs opaque)
/// 3. Routes to the appropriate validator
/// 4. Injects AuthContext into request extensions
#[derive(Clone)]
pub struct AuthInterceptor {
    jwks_cache: Arc<JwksCache>,
    internal_loader: Option<Arc<InternalJwksLoader>>,
    #[allow(dead_code)] // May be used for future auth config checks
    config: Arc<AuthConfig>,
}

impl AuthInterceptor {
    /// Create a new authentication interceptor
    pub fn new(
        jwks_cache: Arc<JwksCache>,
        internal_loader: Option<Arc<InternalJwksLoader>>,
        config: Arc<AuthConfig>,
    ) -> Self {
        Self { jwks_cache, internal_loader, config }
    }

    /// Authenticate a request and return AuthContext
    async fn authenticate(&self, metadata: &MetadataMap) -> Result<AuthContext, AuthError> {
        let start = Instant::now();

        // Extract token from metadata
        let token = match extract_bearer_from_metadata(metadata) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to extract bearer token");
                return Err(e);
            },
        };

        // Detect token type
        let result = if oauth::is_jwt(&token) {
            // JWT token - need to determine if it's tenant, OAuth, or internal
            self.validate_jwt(&token).await
        } else {
            // Opaque token - use introspection if configured
            Err(AuthError::InvalidTokenFormat(
                "Opaque token introspection not yet implemented".to_string(),
            ))
        };

        // Record metrics, audit logs, and log results
        let duration = start.elapsed().as_secs_f64();
        match &result {
            Ok(ctx) => {
                let method = auth_method_to_string(&ctx.auth_method);
                metrics::record_auth_attempt(&method, &ctx.tenant_id);
                metrics::record_auth_success(&method, &ctx.tenant_id, duration);
                tracing::info!(
                    tenant_id = %ctx.tenant_id,
                    method = %method,
                    duration_ms = duration * 1000.0,
                    "Authentication succeeded"
                );

                // Log audit event for successful authentication
                log_audit_event(AuditEvent::AuthenticationSuccess {
                    tenant_id: ctx.tenant_id.clone(),
                    method: method.clone(),
                    timestamp: Utc::now(),
                    ip_address: None, // TODO: Extract from gRPC metadata when available
                });
            },
            Err(e) => {
                let error_type = auth_error_type(e);
                let tenant_id = "unknown";
                let method = "jwt"; // Default to JWT since we extracted a token
                metrics::record_auth_attempt(method, tenant_id);
                metrics::record_auth_failure(method, error_type, tenant_id, duration);
                metrics::record_jwt_validation_error(error_type);
                tracing::warn!(
                    error = %e,
                    error_type = error_type,
                    duration_ms = duration * 1000.0,
                    "Authentication failed"
                );

                // Log audit event for failed authentication
                log_audit_event(AuditEvent::AuthenticationFailure {
                    tenant_id: tenant_id.to_string(),
                    method: method.to_string(),
                    error: e.to_string(),
                    timestamp: Utc::now(),
                    ip_address: None, // TODO: Extract from gRPC metadata when available
                });
            },
        }

        result
    }

    /// Validate JWT token (tenant, OAuth, or internal)
    async fn validate_jwt(&self, token: &str) -> Result<AuthContext, AuthError> {
        // Decode without verification to get issuer claim
        let unverified = jwt::decode_jwt_claims(token)?;

        // Check if this is an internal JWT
        if let Some(ref internal_loader) = self.internal_loader {
            if unverified.iss == internal_loader.issuer() {
                tracing::debug!(issuer = %unverified.iss, "Detected internal service JWT");
                metrics::record_jwt_signature_verification("EdDSA", true);
                return infera_auth::internal::validate_internal_jwt(token, internal_loader).await;
            }
        }

        // Check if issuer matches expected tenant JWKS pattern
        // For tenant JWTs: issuer should be "tenant:{id}"
        if unverified.iss.starts_with("tenant:") {
            tracing::debug!(issuer = %unverified.iss, "Detected tenant JWT");

            // Validate tenant JWT using jwt validation
            let claims = match jwt::verify_with_jwks(token, &self.jwks_cache).await {
                Ok(c) => {
                    metrics::record_jwt_signature_verification("EdDSA", true);
                    c
                },
                Err(e) => {
                    metrics::record_jwt_signature_verification("EdDSA", false);
                    return Err(e);
                },
            };

            // Extract tenant ID and create AuthContext
            let tenant_id = claims.extract_tenant_id()?;
            let scopes = claims.parse_scopes();

            // Extract vault and account UUIDs
            let vault_str = claims.vault.unwrap_or_else(|| uuid::Uuid::nil().to_string());
            let vault = uuid::Uuid::parse_str(&vault_str).unwrap_or(uuid::Uuid::nil());

            let account_str = claims.account.unwrap_or_else(|| uuid::Uuid::nil().to_string());
            let account = uuid::Uuid::parse_str(&account_str).unwrap_or(uuid::Uuid::nil());

            return Ok(AuthContext {
                tenant_id,
                client_id: claims.sub.clone(),
                key_id: String::new(), // TODO: Extract from JWT header
                auth_method: AuthMethod::PrivateKeyJwt,
                scopes,
                issued_at: DateTime::from_timestamp(claims.iat as i64, 0).unwrap_or_else(Utc::now),
                expires_at: DateTime::from_timestamp(claims.exp as i64, 0)
                    .unwrap_or_else(|| Utc::now() + Duration::seconds(300)),
                jti: claims.jti.clone(),
                vault,
                account,
            });
        }

        // Otherwise, try OAuth validation
        tracing::debug!(issuer = %unverified.iss, "Attempting OAuth JWT validation");
        Err(AuthError::InvalidTokenFormat(
            "OAuth JWT validation not yet implemented for gRPC".to_string(),
        ))
    }
}

/// Synchronous interceptor implementation
///
/// This uses futures::executor::block_on which doesn't conflict with tokio runtime
impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let auth_future = self.authenticate(request.metadata());

        // Use futures::executor::block_on instead of tokio::runtime::Handle::block_on
        // This works even when inside a tokio runtime
        let auth_result = futures::executor::block_on(auth_future);

        match auth_result {
            Ok(auth_ctx) => {
                request.extensions_mut().insert(auth_ctx);
                Ok(request)
            },
            Err(e) => Err(auth_error_to_status(e)),
        }
    }
}

/// Convert AuthMethod to string for metrics
fn auth_method_to_string(method: &AuthMethod) -> String {
    match method {
        AuthMethod::PrivateKeyJwt => "tenant_jwt".to_string(),
        AuthMethod::InternalServiceJwt => "internal_jwt".to_string(),
        AuthMethod::OAuthAccessToken => "oauth_jwt".to_string(),
    }
}

/// Extract error type from AuthError for metrics
fn auth_error_type(error: &AuthError) -> &'static str {
    match error {
        AuthError::InvalidTokenFormat(_) => "invalid_format",
        AuthError::TokenExpired => "expired",
        AuthError::TokenNotYetValid => "not_yet_valid",
        AuthError::InvalidSignature => "invalid_signature",
        AuthError::InvalidIssuer(_) => "invalid_issuer",
        AuthError::InvalidAudience(_) => "invalid_audience",
        AuthError::InvalidScope(_) => "invalid_scope",
        AuthError::MissingClaim(_) => "missing_claim",
        AuthError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        AuthError::JwksError(_) => "jwks_error",
        AuthError::OidcDiscoveryFailed(_) => "oidc_discovery_failed",
        AuthError::IntrospectionFailed(_) => "introspection_failed",
        AuthError::InvalidIntrospectionResponse(_) => "invalid_introspection_response",
        AuthError::TokenInactive => "token_inactive",
        AuthError::MissingTenantId => "missing_tenant_id",
        AuthError::ReplayDetected => "replay_detected",
        AuthError::ReplayProtectionError(_) => "replay_protection_error",
        AuthError::TokenTooOld => "token_too_old",
    }
}

/// Convert AuthError to gRPC Status
fn auth_error_to_status(error: AuthError) -> Status {
    match error {
        AuthError::InvalidTokenFormat(_) => Status::unauthenticated(error.to_string()),
        AuthError::TokenExpired => Status::unauthenticated("Token expired"),
        AuthError::TokenNotYetValid => Status::unauthenticated("Token not yet valid"),
        AuthError::InvalidSignature => Status::unauthenticated("Invalid signature"),
        AuthError::InvalidIssuer(_) => Status::unauthenticated(error.to_string()),
        AuthError::InvalidAudience(_) => Status::unauthenticated(error.to_string()),
        AuthError::InvalidScope(_) => Status::permission_denied(error.to_string()),
        AuthError::MissingClaim(_) => Status::unauthenticated(error.to_string()),
        AuthError::UnsupportedAlgorithm(_) => Status::unauthenticated(error.to_string()),
        AuthError::JwksError(_) => Status::internal(error.to_string()),
        AuthError::OidcDiscoveryFailed(_) => Status::internal(error.to_string()),
        AuthError::IntrospectionFailed(_) => Status::internal(error.to_string()),
        AuthError::InvalidIntrospectionResponse(_) => Status::internal(error.to_string()),
        AuthError::TokenInactive => Status::unauthenticated("Token is inactive"),
        AuthError::MissingTenantId => Status::unauthenticated(error.to_string()),
        AuthError::ReplayDetected => Status::unauthenticated("Token replay detected"),
        AuthError::ReplayProtectionError(_) => Status::internal(error.to_string()),
        AuthError::TokenTooOld => Status::unauthenticated("Token is too old"),
    }
}

/// Extract AuthContext from gRPC request extensions
///
/// This helper function should be called at the start of each gRPC handler
/// to retrieve the authenticated context.
///
/// # Errors
///
/// Returns `UNAUTHENTICATED` status if AuthContext is missing from extensions.
#[allow(clippy::result_large_err)]
pub fn extract_auth<T>(request: &Request<T>) -> Result<AuthContext, Status> {
    request
        .extensions()
        .get::<AuthContext>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("Missing authentication context"))
}

#[cfg(test)]
mod tests {
    use tonic::metadata::{MetadataMap, MetadataValue};

    use super::*;

    #[test]
    fn test_extract_bearer_valid() {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", MetadataValue::from_static("Bearer test_token_12345"));

        let result = extract_bearer_from_metadata(&metadata);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_token_12345");
    }

    #[test]
    fn test_extract_bearer_missing() {
        let metadata = MetadataMap::new();
        let result = extract_bearer_from_metadata(&metadata);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing"));
    }

    #[test]
    fn test_extract_bearer_no_prefix() {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", MetadataValue::from_static("test_token_12345"));

        let result = extract_bearer_from_metadata(&metadata);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Bearer"));
    }

    #[test]
    fn test_extract_bearer_empty_token() {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", MetadataValue::from_static("Bearer "));

        let result = extract_bearer_from_metadata(&metadata);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty"));
    }

    #[test]
    fn test_extract_bearer_lowercase_key() {
        // Test that lowercase "authorization" key works
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", MetadataValue::from_static("Bearer lowercase_works"));

        let result = extract_bearer_from_metadata(&metadata);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "lowercase_works");
    }
}
