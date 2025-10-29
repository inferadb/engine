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

use infera_auth::{
    context::{AuthContext, AuthMethod}, error::AuthError, internal::InternalJwksLoader, jwks_cache::JwksCache,
    jwt, oauth,
};
use infera_config::AuthConfig;
use std::sync::Arc;
use tonic::{metadata::MetadataMap, Request, Status};

// Re-export chrono from infera_auth's context module
use chrono::{DateTime, Duration, Utc};

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
    let auth_value = metadata
        .get("authorization")
        .ok_or_else(|| AuthError::InvalidTokenFormat("Missing authorization metadata".to_string()))?;

    // Convert metadata value to string
    let auth_str = auth_value
        .to_str()
        .map_err(|_| AuthError::InvalidTokenFormat("Invalid authorization header encoding".to_string()))?;

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
        Self {
            jwks_cache,
            internal_loader,
            config,
        }
    }

    /// Authenticate a request and return AuthContext
    async fn authenticate(&self, metadata: &MetadataMap) -> Result<AuthContext, AuthError> {
        // Extract token from metadata
        let token = extract_bearer_from_metadata(metadata)?;

        // Detect token type
        if oauth::is_jwt(&token) {
            // JWT token - need to determine if it's tenant, OAuth, or internal
            self.validate_jwt(&token).await
        } else {
            // Opaque token - use introspection if configured
            Err(AuthError::InvalidTokenFormat(
                "Opaque token introspection not yet implemented".to_string(),
            ))
        }
    }

    /// Validate JWT token (tenant, OAuth, or internal)
    async fn validate_jwt(&self, token: &str) -> Result<AuthContext, AuthError> {
        // Decode without verification to get issuer claim
        let unverified = jwt::decode_jwt_claims(token)?;

        // Check if this is an internal JWT
        if let Some(ref internal_loader) = self.internal_loader {
            if unverified.iss == internal_loader.issuer() {
                tracing::debug!("Detected internal service JWT");
                return infera_auth::internal::validate_internal_jwt(token, internal_loader).await;
            }
        }

        // Check if issuer matches expected tenant JWKS pattern
        // For tenant JWTs: issuer should be "tenant:{id}"
        if unverified.iss.starts_with("tenant:") {
            tracing::debug!(issuer = %unverified.iss, "Detected tenant JWT");
            // Validate tenant JWT using jwt validation
            let claims = jwt::verify_with_jwks(token, &self.jwks_cache).await?;

            // Extract tenant ID and create AuthContext
            let tenant_id = claims.extract_tenant_id()?;
            let scopes = claims.parse_scopes();

            return Ok(AuthContext {
                tenant_id,
                client_id: claims.sub.clone(),
                key_id: String::new(), // TODO: Extract from JWT header
                auth_method: AuthMethod::PrivateKeyJwt,
                scopes,
                issued_at: DateTime::from_timestamp(claims.iat as i64, 0)
                    .unwrap_or_else(Utc::now),
                expires_at: DateTime::from_timestamp(claims.exp as i64, 0)
                    .unwrap_or_else(|| Utc::now() + Duration::seconds(300)),
                jti: claims.jti.clone(),
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
            }
            Err(e) => Err(auth_error_to_status(e)),
        }
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
    use super::*;
    use tonic::metadata::{MetadataMap, MetadataValue};

    #[test]
    fn test_extract_bearer_valid() {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            MetadataValue::from_static("Bearer test_token_12345"),
        );

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
        metadata.insert(
            "authorization",
            MetadataValue::from_static("test_token_12345"),
        );

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
        metadata.insert(
            "authorization",
            MetadataValue::from_static("Bearer lowercase_works"),
        );

        let result = extract_bearer_from_metadata(&metadata);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "lowercase_works");
    }
}
