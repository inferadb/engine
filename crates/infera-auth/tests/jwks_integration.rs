mod common;

use std::{sync::Arc, time::Duration};

use common::mock_jwks::{generate_jwt_for_mock_jwks, start_mock_jwks_server};
use infera_auth::jwks_cache::{JwksCache, JwksCacheKey};
use moka::future::Cache;

#[tokio::test]
async fn test_jwks_cache_with_mock_server() {
    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Fetch JWKS for tenant
    let keys = jwks_cache.get_jwks("acme").await.expect("Failed to fetch JWKS");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kty, "OKP");
    assert_eq!(keys[0].alg, Some("EdDSA".to_string()));
    assert_eq!(keys[0].kid, "acme-key-001");
}

#[tokio::test]
async fn test_jwks_cache_hit() {
    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache.clone(), Duration::from_secs(300)).unwrap();

    // First fetch - cache miss
    let keys1 = jwks_cache.get_jwks("acme").await.expect("Failed to fetch JWKS");

    // Verify cache was populated
    let cache_key = JwksCacheKey { tenant_id: "acme".to_string() };
    assert!(cache.get(&cache_key).await.is_some());

    // Second fetch - cache hit
    let keys2 = jwks_cache.get_jwks("acme").await.expect("Failed to fetch JWKS");

    assert_eq!(keys1.len(), keys2.len());
    assert_eq!(keys1[0].kid, keys2[0].kid);
}

#[tokio::test]
async fn test_jwks_get_key_by_id() {
    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Get specific key by ID
    let key =
        jwks_cache.get_key_by_id("acme", "acme-key-001").await.expect("Failed to get key by ID");

    assert_eq!(key.kid, "acme-key-001");
    assert_eq!(key.kty, "OKP");
    assert_eq!(key.alg, Some("EdDSA".to_string()));
}

#[tokio::test]
async fn test_jwks_key_not_found() {
    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Try to get non-existent key
    let result = jwks_cache.get_key_by_id("acme", "nonexistent-key").await;

    assert!(result.is_err());
    match result {
        Err(e) => assert!(e.to_string().contains("not found")),
        Ok(_) => panic!("Expected error for non-existent key"),
    }
}

#[tokio::test]
async fn test_concurrent_requests_deduplication() {
    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = Arc::new(JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap());

    // Launch 10 concurrent requests for the same tenant
    let mut handles = vec![];
    for _ in 0..10 {
        let cache_clone = jwks_cache.clone();
        let handle = tokio::spawn(async move { cache_clone.get_jwks("concurrent-test").await });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let results: Vec<_> = futures::future::join_all(handles).await;

    // All requests should succeed
    for result in results {
        assert!(result.is_ok());
        let keys = result.unwrap().expect("Failed to fetch JWKS");
        assert_eq!(keys.len(), 1);
    }
}

#[tokio::test]
async fn test_stale_while_revalidate() {
    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create cache with very short TTL (1 second)
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(1)).unwrap();

    // First fetch
    let keys1 = jwks_cache.get_jwks("stale-test").await.expect("Failed to fetch JWKS");

    // Wait for TTL to expire
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Second fetch - should return stale value and trigger background refresh
    let keys2 = jwks_cache.get_jwks("stale-test").await.expect("Failed to fetch JWKS");

    // Both should be identical (stale value returned)
    assert_eq!(keys1[0].kid, keys2[0].kid);

    // Wait for background refresh to complete
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Third fetch should still work
    let keys3 = jwks_cache.get_jwks("stale-test").await.expect("Failed to fetch JWKS");

    assert_eq!(keys1[0].kid, keys3[0].kid);
}

#[tokio::test]
async fn test_stale_while_revalidate_with_failed_refresh() {
    // Start mock JWKS server
    let (base_url, handle) = start_mock_jwks_server().await;

    // Create cache with very short TTL (1 second)
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(1)).unwrap();

    // First fetch - populate cache
    let keys1 = jwks_cache.get_jwks("stale-test").await.expect("Failed to fetch JWKS");

    // Wait for TTL to expire
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Stop the mock server to simulate network failure
    drop(handle);

    // Second fetch - should return stale value despite background refresh failure
    let keys2 = jwks_cache
        .get_jwks("stale-test")
        .await
        .expect("Should return stale JWKS even though server is down");

    // Should still get the same stale data
    assert_eq!(keys1[0].kid, keys2[0].kid);

    // Wait for background refresh to fail
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Third fetch should still return stale data (background refresh failed)
    let keys3 = jwks_cache
        .get_jwks("stale-test")
        .await
        .expect("Should continue to serve stale JWKS after failed refresh");

    // All keys should be identical - still serving original stale cache
    assert_eq!(keys1[0].kid, keys3[0].kid);
}

#[tokio::test]
async fn test_multi_tenant_isolation() {
    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Fetch JWKS for multiple tenants
    let keys_acme = jwks_cache.get_jwks("acme").await.expect("Failed to fetch JWKS for acme");

    let keys_globex = jwks_cache.get_jwks("globex").await.expect("Failed to fetch JWKS for globex");

    // Keys should be different for different tenants
    assert_ne!(keys_acme[0].kid, keys_globex[0].kid);
    assert_eq!(keys_acme[0].kid, "acme-key-001");
    assert_eq!(keys_globex[0].kid, "globex-key-001");
}

#[tokio::test]
async fn test_jwt_verification_with_jwks() {
    use infera_auth::jwt::decode_jwt_claims;

    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Generate a valid JWT for tenant "acme"
    let jwt = generate_jwt_for_mock_jwks("acme", vec!["inferadb.evaluate".to_string()], 300);

    // Decode JWT claims (this doesn't verify signature yet, but tests JWT structure)
    let claims = decode_jwt_claims(&jwt).expect("Failed to decode JWT");

    assert_eq!(claims.iss, "tenant:acme");
    assert_eq!(claims.sub, "tenant:acme");
    assert_eq!(claims.scope, "inferadb.evaluate".to_string());

    // Verify tenant extraction
    let tenant_id = claims.extract_tenant_id().expect("Failed to extract tenant");
    assert_eq!(tenant_id, "acme");

    // Create JWKS cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Fetch the key used to sign this JWT
    let key = jwks_cache
        .get_key_by_id(&tenant_id, "acme-key-001")
        .await
        .expect("Failed to get signing key");

    // Verify key structure
    assert_eq!(key.kty, "OKP");
    assert_eq!(key.alg, Some("EdDSA".to_string()));
}

#[tokio::test]
async fn test_verify_with_jwks_success() {
    use infera_auth::jwt::verify_with_jwks;

    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create JWKS cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Generate a valid JWT for tenant "acme"
    let jwt = generate_jwt_for_mock_jwks("acme", vec!["inferadb.evaluate".to_string()], 300);

    // Verify JWT signature using JWKS cache
    let claims = verify_with_jwks(&jwt, &jwks_cache).await.expect("Failed to verify JWT with JWKS");

    assert_eq!(claims.iss, "tenant:acme");
    assert_eq!(claims.sub, "tenant:acme");
    assert_eq!(claims.scope, "inferadb.evaluate".to_string());
}

#[tokio::test]
async fn test_verify_with_jwks_cached_key() {
    use infera_auth::jwt::verify_with_jwks;

    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create JWKS cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Generate two JWTs for the same tenant
    let jwt1 = generate_jwt_for_mock_jwks("acme", vec!["inferadb.evaluate".to_string()], 300);
    let jwt2 = generate_jwt_for_mock_jwks("acme", vec!["inferadb.check".to_string()], 300);

    // First verification - cache miss
    let claims1 = verify_with_jwks(&jwt1, &jwks_cache).await.expect("Failed to verify JWT 1");

    assert_eq!(claims1.iss, "tenant:acme");

    // Second verification - cache hit (same tenant, same key)
    let claims2 = verify_with_jwks(&jwt2, &jwks_cache).await.expect("Failed to verify JWT 2");

    assert_eq!(claims2.iss, "tenant:acme");
    assert_eq!(claims2.scope, "inferadb.check".to_string());
}

#[tokio::test]
async fn test_verify_with_jwks_missing_kid() {
    use infera_auth::jwt::verify_with_jwks;

    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create JWKS cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Create a JWT without kid (manually constructed)
    let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZW5hbnQ6YWNtZSIsInN1YiI6InRlbmFudDphY21lIiwiYXVkIjoiaHR0cHM6Ly9hcGkuaW5mZXJhZGIuY29tL2V2YWx1YXRlIiwiZXhwIjoxNzMwMDAwMDYwLCJpYXQiOjE3MzAwMDAwMDAsInNjb3BlIjoiaW5mZXJhZGIuZXZhbHVhdGUifQ.fake";

    // Verify should fail due to missing kid
    let result = verify_with_jwks(token, &jwks_cache).await;

    assert!(result.is_err());
    match result {
        Err(e) => assert!(e.to_string().contains("missing 'kid'")),
        Ok(_) => panic!("Expected error for missing kid"),
    }
}

#[tokio::test]
async fn test_verify_with_jwks_key_rotation() {
    use infera_auth::jwt::verify_with_jwks;

    // Start mock JWKS server
    let (base_url, _handle) = start_mock_jwks_server().await;

    // Create JWKS cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Generate JWT for tenant "rotation-test"
    let jwt =
        generate_jwt_for_mock_jwks("rotation-test", vec!["inferadb.evaluate".to_string()], 300);

    // First verification should succeed
    let claims = verify_with_jwks(&jwt, &jwks_cache).await.expect("Failed to verify JWT");

    assert_eq!(claims.iss, "tenant:rotation-test");

    // The key is now cached. If we try to verify again, it should use cached key
    let claims2 =
        verify_with_jwks(&jwt, &jwks_cache).await.expect("Failed to verify JWT with cached key");

    assert_eq!(claims2.iss, "tenant:rotation-test");
}

#[tokio::test]
async fn test_jwks_fetch_404_error() {
    // Create cache with non-existent server
    let cache = Arc::new(Cache::new(100));
    let jwks_cache =
        JwksCache::new("http://127.0.0.1:1".to_string(), cache, Duration::from_secs(300)).unwrap();

    // Try to fetch JWKS - should fail due to connection error
    let result = jwks_cache.get_jwks("nonexistent").await;

    assert!(result.is_err());
    match result {
        Err(e) => {
            let err_str = e.to_string();
            // Should be a network or HTTP error
            assert!(err_str.contains("JWKS") || err_str.contains("error"));
        },
        Ok(_) => panic!("Expected error for non-existent server"),
    }
}

#[tokio::test]
async fn test_jwks_malformed_response() {
    use axum::{Router, routing::get};

    // Start a server that returns malformed JSON
    async fn malformed_handler() -> &'static str {
        "{ invalid json"
    }

    let app = Router::new().route("/jwks/:tenant", get(malformed_handler));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", local_addr);

    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Try to fetch JWKS - should fail due to malformed JSON
    let result = jwks_cache.get_jwks("test").await;

    assert!(result.is_err());
    match result {
        Err(e) => {
            let err_str = e.to_string();
            // Should be a JSON parsing error
            assert!(err_str.contains("JWKS") || err_str.contains("error"));
        },
        Ok(_) => panic!("Expected error for malformed JSON"),
    }
}

#[tokio::test]
async fn test_jwks_empty_keys_array() {
    use axum::{Json, Router, routing::get};

    // Start a server that returns empty keys array
    async fn empty_keys_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "keys": []
        }))
    }

    let app = Router::new().route("/jwks/:tenant", get(empty_keys_handler));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", local_addr);

    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create cache
    let cache = Arc::new(Cache::new(100));
    let jwks_cache = JwksCache::new(base_url, cache, Duration::from_secs(300)).unwrap();

    // Try to fetch JWKS - should fail due to empty keys
    let result = jwks_cache.get_jwks("test").await;

    assert!(result.is_err());
    match result {
        Err(e) => {
            let err_str = e.to_string();
            println!("Error message: {}", err_str);
            // Check for error about empty or no keys
            assert!(
                err_str.contains("JWKS")
                    && (err_str.contains("empty") || err_str.contains("no keys"))
            );
        },
        Ok(_) => panic!("Expected error for empty keys array"),
    }
}
