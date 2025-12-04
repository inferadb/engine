//! OAuth Integration Tests
//!
//! Tests for OAuth 2.0 JWT validation, OIDC discovery, and token introspection

mod common;

use std::{sync::Arc, time::Duration};

use common::mock_oauth::{
    generate_oauth_jwt, generate_opaque_token, register_opaque_token, start_mock_oauth_server,
};
use infera_auth::{
    jwks_cache::JwksCache,
    oauth::{IntrospectionClient, IntrospectionResponse, OAuthJwksClient},
    oidc::OidcDiscoveryClient,
};
use infera_types::AuthMethod;
use moka::future::Cache;

/// Test OAuth JWT validation end-to-end
#[tokio::test]
async fn test_oauth_jwt_validation() {
    let (base_url, _handle, _state) = start_mock_oauth_server().await;

    // Generate valid OAuth JWT with the mock server as the issuer
    let token = generate_oauth_jwt(&base_url, "acme", vec!["read", "write"], 300);

    // Create OIDC discovery client
    let oidc_client = Arc::new(OidcDiscoveryClient::new(Duration::from_secs(300)).unwrap());

    // Create JWKS cache
    let jwks_cache = Arc::new(
        JwksCache::new(base_url.clone(), Arc::new(Cache::new(100)), Duration::from_secs(300))
            .unwrap(),
    );

    // Create OAuth client
    let client = OAuthJwksClient::new(oidc_client, jwks_cache);

    // Fetch JWKS from OAuth server (via OIDC discovery)
    let jwks = client.fetch_oauth_jwks(&base_url).await.expect("Failed to fetch OAuth JWKS");

    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].kid, "oauth-test-key-001");
    assert_eq!(jwks[0].alg, Some("EdDSA".to_string()));

    // Validate OAuth JWT (this is what will be called from gRPC interceptor)
    let auth_ctx = infera_auth::oauth::validate_oauth_jwt(
        &token,
        &client,
        Some("https://api.inferadb.com/evaluate"),
    )
    .await
    .expect("Failed to validate OAuth JWT");

    // Verify AuthContext extracted correctly
    assert_eq!(auth_ctx.organization, 98765432109876); // org_id from JWT claims
    assert_eq!(auth_ctx.auth_method, AuthMethod::OAuthAccessToken);
    assert_eq!(auth_ctx.scopes, vec!["read", "write"]);
    assert!(auth_ctx.client_id.starts_with("user-"));
}

/// Test OAuth JWT validation with expired token
#[tokio::test]
async fn test_oauth_jwt_validation_expired() {
    let (base_url, _handle, _state) = start_mock_oauth_server().await;

    // Generate expired OAuth JWT (exp in past)
    let token = generate_oauth_jwt(&base_url, "acme", vec!["read"], -300);

    // Create OAuth client
    let oidc_client = Arc::new(OidcDiscoveryClient::new(Duration::from_secs(300)).unwrap());
    let jwks_cache = Arc::new(
        JwksCache::new(base_url.clone(), Arc::new(Cache::new(100)), Duration::from_secs(300))
            .unwrap(),
    );
    let client = OAuthJwksClient::new(oidc_client, jwks_cache);

    // Validate OAuth JWT - should fail with TokenExpired
    let result = infera_auth::oauth::validate_oauth_jwt(
        &token,
        &client,
        Some("https://api.inferadb.com/evaluate"),
    )
    .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), infera_auth::error::AuthError::TokenExpired));
}

/// Test OIDC discovery
#[tokio::test]
async fn test_oidc_discovery() {
    let (base_url, _handle, _state) = start_mock_oauth_server().await;

    // Create OIDC discovery client
    let client = OidcDiscoveryClient::new(Duration::from_secs(300)).unwrap();

    // Discover OIDC configuration
    let config = client.discover(&base_url).await.expect("Failed to discover OIDC configuration");

    // Verify configuration extracted correctly
    assert_eq!(config.issuer, base_url);
    assert_eq!(config.jwks_uri, format!("{}/jwks.json", base_url));
    assert_eq!(config.token_endpoint, format!("{}/token", base_url));
    assert_eq!(config.introspection_endpoint, Some(format!("{}/introspect", base_url)));
}

/// Test OIDC discovery caching
#[tokio::test]
async fn test_oidc_discovery_caching() {
    let (base_url, _handle, _state) = start_mock_oauth_server().await;

    // Create OIDC discovery client with cache
    let client = OidcDiscoveryClient::new(Duration::from_secs(300)).unwrap();

    // First discovery - cache miss
    let config1 = client.discover(&base_url).await.expect("Failed to discover OIDC configuration");

    // Second discovery - cache hit (should be instant)
    let config2 =
        client.discover(&base_url).await.expect("Failed to discover OIDC configuration (cached)");

    // Both configs should be identical
    assert_eq!(config1.issuer, config2.issuer);
    assert_eq!(config1.jwks_uri, config2.jwks_uri);
    assert_eq!(config1.token_endpoint, config2.token_endpoint);
}

/// Test token introspection with registered opaque token
#[tokio::test]
async fn test_token_introspection_active() {
    let (base_url, _handle, state) = start_mock_oauth_server().await;

    // Generate opaque token
    let token = generate_opaque_token();

    // Register token with metadata
    let metadata = IntrospectionResponse {
        active: true,
        scope: Some("read write".to_string()),
        client_id: Some("test-client".to_string()),
        username: Some("testuser".to_string()),
        token_type: Some("Bearer".to_string()),
        exp: Some(9999999999),
        iat: Some(1234567890),
        sub: Some("user-123".to_string()),
    };
    register_opaque_token(&state, &token, metadata.clone());

    // Create introspection client
    let client = IntrospectionClient::new().unwrap();

    // Introspect token
    let result = client
        .introspect(&token, &format!("{}/introspect", base_url))
        .await
        .expect("Failed to introspect token");

    // Verify result
    assert!(result.active);
    assert_eq!(result.sub, Some("user-123".to_string()));
    assert_eq!(result.scope, Some("read write".to_string()));
    assert_eq!(result.client_id, Some("test-client".to_string()));
}

/// Test token introspection with inactive token
#[tokio::test]
async fn test_token_introspection_inactive() {
    let (base_url, _handle, _state) = start_mock_oauth_server().await;

    // Generate unregistered opaque token
    let token = generate_opaque_token();

    // Create introspection client
    let client = IntrospectionClient::new().unwrap();

    // Introspect unregistered token
    let result = client
        .introspect(&token, &format!("{}/introspect", base_url))
        .await
        .expect("Failed to introspect token");

    // Verify inactive response
    assert!(!result.active);
    assert_eq!(result.sub, None);
    assert_eq!(result.scope, None);
}

/// Test introspection caching
#[tokio::test]
async fn test_token_introspection_caching() {
    let (base_url, _handle, state) = start_mock_oauth_server().await;

    // Generate and register opaque token
    let token = generate_opaque_token();
    let metadata = IntrospectionResponse {
        active: true,
        scope: Some("read".to_string()),
        client_id: Some("cache-test".to_string()),
        username: Some("cacheuser".to_string()),
        token_type: Some("Bearer".to_string()),
        exp: Some(9999999999),
        iat: Some(1234567890),
        sub: Some("user-456".to_string()),
    };
    register_opaque_token(&state, &token, metadata);

    // Create introspection client with cache
    let client = IntrospectionClient::new_with_cache(100, Duration::from_secs(60)).unwrap();

    // First introspection - cache miss
    let result1 = client
        .introspect(&token, &format!("{}/introspect", base_url))
        .await
        .expect("Failed to introspect token");

    // Second introspection - cache hit (should be instant)
    let result2 = client
        .introspect(&token, &format!("{}/introspect", base_url))
        .await
        .expect("Failed to introspect token (cached)");

    // Both results should be identical
    assert_eq!(result1.active, result2.active);
    assert_eq!(result1.sub, result2.sub);
    assert_eq!(result1.scope, result2.scope);
}

/// Test OAuth JWT with org_id claim
#[tokio::test]
async fn test_oauth_jwt_with_org_id() {
    // This test verifies behavior when OAuth JWT has org_id claim (Management API spec)
    let (base_url, _handle, _state) = start_mock_oauth_server().await;

    // Generate OAuth JWT with org_id
    let token = generate_oauth_jwt(&base_url, "acme", vec!["read"], 300);

    // Create OAuth client
    let oidc_client = Arc::new(OidcDiscoveryClient::new(Duration::from_secs(300)).unwrap());
    let jwks_cache = Arc::new(
        JwksCache::new(base_url.clone(), Arc::new(Cache::new(100)), Duration::from_secs(300))
            .unwrap(),
    );
    let client = OAuthJwksClient::new(oidc_client, jwks_cache);

    // Validate OAuth JWT
    let auth_ctx = infera_auth::oauth::validate_oauth_jwt(
        &token,
        &client,
        Some("https://api.inferadb.com/evaluate"),
    )
    .await
    .expect("Failed to validate OAuth JWT");

    // Should extract org_id from JWT claims
    assert_eq!(auth_ctx.organization, 98765432109876); // org_id Snowflake ID parsed as i64
}
