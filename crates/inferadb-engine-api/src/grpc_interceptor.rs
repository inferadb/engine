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
//! use crate::grpc_interceptor::LedgerAuthInterceptor;
//!
//! let interceptor = LedgerAuthInterceptor::new(signing_key_cache, internal_loader, config);
//!
//! Server::builder()
//!     .add_service(AuthorizationServiceServer::with_interceptor(service, interceptor))
//!     .serve(addr)
//!     .await?;
//! ```

use std::{sync::Arc, time::Instant};

// Re-export chrono from inferadb_auth's context module
use chrono::{DateTime, Duration, Utc};
use inferadb_engine_auth::{
    audit::{AuditEvent, log_audit_event},
    error::AuthError,
    internal::InternalJwksLoader,
    jwt,
    signing_key_cache::SigningKeyCache,
};
use inferadb_engine_config::TokenConfig;
use inferadb_engine_observe::metrics;
use inferadb_engine_types::{AuthContext, AuthMethod};
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

// Note: AuthInterceptor (JWKS-based) has been removed.
// Use LedgerAuthInterceptor for authentication with Ledger-backed signing keys.

/// gRPC Authentication Interceptor using Ledger-backed signing keys
///
/// This interceptor uses `SigningKeyCache` to fetch signing keys directly from Ledger,
/// eliminating the need for JWKS endpoints and Control connectivity.
///
/// It supports:
/// - Tenant JWTs (from SDK/CLI) verified against Ledger signing keys
/// - Internal service JWTs (if internal_loader is provided)
///
/// ## Usage
///
/// ```ignore
/// use tonic::transport::Server;
/// use crate::grpc_interceptor::LedgerAuthInterceptor;
///
/// let interceptor = LedgerAuthInterceptor::new(signing_key_cache, internal_loader, config);
///
/// Server::builder()
///     .add_service(AuthorizationServiceServer::with_interceptor(service, interceptor))
///     .serve(addr)
///     .await?;
/// ```
#[derive(Clone)]
pub struct LedgerAuthInterceptor {
    signing_key_cache: Arc<SigningKeyCache>,
    internal_loader: Option<Arc<InternalJwksLoader>>,
    #[allow(dead_code)] // May be used for future token validation config
    config: Arc<TokenConfig>,
}

impl LedgerAuthInterceptor {
    /// Create a new Ledger-backed authentication interceptor
    pub fn new(
        signing_key_cache: Arc<SigningKeyCache>,
        internal_loader: Option<Arc<InternalJwksLoader>>,
        config: Arc<TokenConfig>,
    ) -> Self {
        Self { signing_key_cache, internal_loader, config }
    }

    /// Authenticate a gRPC request using Ledger-backed signing keys
    async fn authenticate(&self, metadata: &MetadataMap) -> Result<AuthContext, AuthError> {
        let start = Instant::now();

        // Extract bearer token
        let token = match extract_bearer_from_metadata(metadata) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to extract bearer token");
                return Err(e);
            },
        };

        // Determine if JWT (starts with eyJ) or opaque token
        let result = if token.starts_with("eyJ") {
            // JWT path
            self.validate_jwt(&token).await
        } else {
            // Opaque tokens not supported
            Err(AuthError::InvalidTokenFormat(
                "Opaque tokens not supported - please use JWT".to_string(),
            ))
        };

        // Record metrics, audit logs, and log results
        let duration = start.elapsed().as_secs_f64();
        match &result {
            Ok(ctx) => {
                let method = auth_method_to_string(&ctx.auth_method);
                let org_id_str = ctx.organization.to_string();
                metrics::record_auth_attempt(&method, &org_id_str);
                metrics::record_auth_success(&method, &org_id_str, duration);
                tracing::info!(
                    organization = %ctx.organization,
                    method = %method,
                    duration_ms = duration * 1000.0,
                    "Authentication succeeded (Ledger keys)"
                );

                // Log audit event for successful authentication
                log_audit_event(AuditEvent::AuthenticationSuccess {
                    tenant_id: org_id_str,
                    method: method.clone(),
                    timestamp: Utc::now(),
                    ip_address: None,
                });
            },
            Err(e) => {
                let error_type = auth_error_type(e);
                let org_id = "unknown";
                let method = "jwt";
                metrics::record_auth_attempt(method, org_id);
                metrics::record_auth_failure(method, error_type, org_id, duration);
                metrics::record_jwt_validation_error(error_type);
                tracing::warn!(
                    error = %e,
                    error_type = error_type,
                    duration_ms = duration * 1000.0,
                    "Authentication failed (Ledger keys)"
                );

                // Log audit event for failed authentication
                log_audit_event(AuditEvent::AuthenticationFailure {
                    tenant_id: org_id.to_string(),
                    method: method.to_string(),
                    error: e.to_string(),
                    timestamp: Utc::now(),
                    ip_address: None,
                });
            },
        }

        result
    }

    /// Validate JWT token (tenant or internal)
    async fn validate_jwt(&self, token: &str) -> Result<AuthContext, AuthError> {
        // Decode without verification to get issuer claim
        let unverified = jwt::decode_jwt_claims(token)?;

        // Check if this is an internal JWT
        if let Some(ref internal_loader) = self.internal_loader
            && unverified.iss == internal_loader.issuer()
        {
            tracing::debug!(issuer = %unverified.iss, "Detected internal service JWT");
            metrics::record_jwt_signature_verification("EdDSA", true);
            return inferadb_engine_auth::internal::validate_internal_jwt(token, internal_loader)
                .await;
        }

        // Validate tenant JWT using Ledger-backed signing key cache
        tracing::debug!(issuer = %unverified.iss, "Validating tenant JWT using Ledger keys");

        let claims = match jwt::verify_with_signing_key_cache(token, &self.signing_key_cache).await
        {
            Ok(c) => {
                metrics::record_jwt_signature_verification("EdDSA", true);
                c
            },
            Err(e) => {
                metrics::record_jwt_signature_verification("EdDSA", false);
                return Err(e);
            },
        };

        // Extract organization ID and create AuthContext
        let scopes = claims.parse_scopes();

        // Extract vault and organization IDs
        let vault = claims.vault_id.as_ref().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);

        let organization = claims.org_id.as_ref().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);

        Ok(AuthContext {
            client_id: claims.sub.clone(),
            key_id: String::new(), // Will be populated from JWT header in future
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes,
            issued_at: DateTime::from_timestamp(claims.iat as i64, 0).unwrap_or_else(Utc::now),
            expires_at: DateTime::from_timestamp(claims.exp as i64, 0)
                .unwrap_or_else(|| Utc::now() + Duration::seconds(300)),
            jti: claims.jti.clone(),
            vault,
            organization,
        })
    }
}

/// Synchronous interceptor implementation for LedgerAuthInterceptor
///
/// Uses tokio::task::block_in_place to safely block within a tokio runtime context.
impl tonic::service::Interceptor for LedgerAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let auth_future = self.authenticate(request.metadata());

        // Use tokio::task::block_in_place to block safely within the tokio runtime.
        let auth_result =
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(auth_future));

        match auth_result {
            Ok(auth_ctx) => {
                request.extensions_mut().insert(Arc::new(auth_ctx));
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
        AuthError::MissingTenantId => "missing_org_id",
        AuthError::TokenTooOld => "token_too_old",
        // Ledger-backed signing key errors
        AuthError::KeyNotFound { .. } => "key_not_found",
        AuthError::KeyInactive { .. } => "key_inactive",
        AuthError::KeyRevoked { .. } => "key_revoked",
        AuthError::KeyNotYetValid { .. } => "key_not_yet_valid",
        AuthError::KeyExpired { .. } => "key_expired",
        AuthError::InvalidPublicKey(_) => "invalid_public_key",
        AuthError::KeyStorageError(_) => "key_storage_error",
    }
}

/// Convert AuthError to gRPC Status
///
/// Security: Signing key errors return a generic message to prevent
/// information leakage about key existence and state. The specific
/// error is logged internally for debugging.
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
        AuthError::TokenTooOld => Status::unauthenticated("Token is too old"),
        // Ledger-backed signing key errors - use generic message to prevent key enumeration
        AuthError::KeyNotFound { ref kid }
        | AuthError::KeyInactive { ref kid }
        | AuthError::KeyRevoked { ref kid }
        | AuthError::KeyNotYetValid { ref kid }
        | AuthError::KeyExpired { ref kid } => {
            // Log specific error internally for debugging
            tracing::debug!(kid = %kid, error = %error, "Signing key validation failed");
            Status::unauthenticated("Authentication failed")
        },
        AuthError::InvalidPublicKey(ref msg) => {
            tracing::debug!(error = %msg, "Invalid public key format");
            Status::unauthenticated("Authentication failed")
        },
        AuthError::KeyStorageError(_) => Status::internal("Authentication service unavailable"),
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
        .get::<Arc<AuthContext>>()
        .map(|arc| (**arc).clone())
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
