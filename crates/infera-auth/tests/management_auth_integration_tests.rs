//! Integration tests for Management API authentication
//!
//! These tests verify the integration between the InferaDB server and the Management API
//! for JWT authentication, vault verification, and organization status checks.

mod common;

use std::{sync::Arc, time::Duration};

use common::mock_management::{
    MockManagementState, create_test_certificate, create_test_organization, create_test_vault,
    generate_jwt_with_key, generate_snowflake_id, start_mock_management_server,
};
use infera_auth::{
    certificate_cache::{CertificateCache, ParsedKeyId},
    management_client::{ManagementClient, OrgStatus},
    vault_verification::{ManagementApiVaultVerifier, VaultVerifier},
};

// ============================================================================
// Certificate Cache Tests
// ============================================================================

#[tokio::test]
async fn test_certificate_cache_fetch_and_cache() {
    // Setup mock server
    let state = MockManagementState::new();
    let org_id = generate_snowflake_id();
    let client_id = generate_snowflake_id();
    let (cert, _signing_key) = create_test_certificate(org_id, client_id);
    let cert_id = cert.id;
    state.add_certificate(cert);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create certificate cache
    let cache = CertificateCache::new(base_url, Duration::from_secs(300), 100)
        .expect("Failed to create certificate cache");

    // Fetch certificate (should cache miss, then fetch from API)
    let kid = format!("org-{}-client-{}-cert-{}", org_id, client_id, cert_id);
    let decoding_key = cache.get_decoding_key(&kid).await.expect("Failed to get decoding key");

    // Fetch again (should be cache hit)
    let decoding_key2 =
        cache.get_decoding_key(&kid).await.expect("Failed to get decoding key on second call");

    // Both should point to the same Arc instance
    assert!(Arc::ptr_eq(&decoding_key, &decoding_key2));
}

#[tokio::test]
async fn test_certificate_cache_not_found() {
    // Setup mock server with no certificates
    let state = MockManagementState::new();
    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create certificate cache
    let cache = CertificateCache::new(base_url, Duration::from_secs(300), 100)
        .expect("Failed to create certificate cache");

    // Try to fetch non-existent certificate
    let kid = format!(
        "org-{}-client-{}-cert-{}",
        generate_snowflake_id(),
        generate_snowflake_id(),
        generate_snowflake_id()
    );
    let result = cache.get_decoding_key(&kid).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("not found"));
}

#[tokio::test]
async fn test_certificate_cache_invalid_kid_format() {
    // Setup mock server
    let state = MockManagementState::new();
    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create certificate cache
    let cache = CertificateCache::new(base_url, Duration::from_secs(300), 100)
        .expect("Failed to create certificate cache");

    // Try various invalid kid formats
    let invalid_kids =
        vec!["invalid-kid", "org-only", "org-12345", "wrong-12345-client-67890-cert-11111"];

    for kid in invalid_kids {
        let result = cache.get_decoding_key(kid).await;
        assert!(result.is_err(), "Expected error for kid: {}", kid);
    }
}

#[tokio::test]
async fn test_certificate_cache_concurrent_requests() {
    // Setup mock server
    let state = MockManagementState::new();
    let org_id = generate_snowflake_id();
    let client_id = generate_snowflake_id();
    let (cert, _signing_key) = create_test_certificate(org_id, client_id);
    let cert_id = cert.id;
    state.add_certificate(cert);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create certificate cache
    let cache = std::sync::Arc::new(
        CertificateCache::new(base_url, Duration::from_secs(300), 100)
            .expect("Failed to create certificate cache"),
    );

    let kid = format!("org-{}-client-{}-cert-{}", org_id, client_id, cert_id);

    // Launch multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..10 {
        let cache_clone = cache.clone();
        let kid_clone = kid.clone();
        let handle = tokio::spawn(async move { cache_clone.get_decoding_key(&kid_clone).await });
        handles.push(handle);
    }

    // All should succeed
    for handle in handles {
        let result = handle.await.expect("Task panicked");
        assert!(result.is_ok(), "Concurrent request failed");
    }
}

#[test]
fn test_parsed_key_id_valid() {
    let org_id = 11897886526013449i64;
    let client_id = 11897886528110597i64;
    let cert_id = 11897886528176133i64;

    let kid = format!("org-{}-client-{}-cert-{}", org_id, client_id, cert_id);

    let parsed = ParsedKeyId::parse(&kid).expect("Failed to parse valid kid");

    assert_eq!(parsed.org_id, org_id);
    assert_eq!(parsed.client_id, client_id);
    assert_eq!(parsed.cert_id, cert_id);
}

// ============================================================================
// Vault Verification Tests
// ============================================================================

#[tokio::test]
async fn test_vault_verification_success() {
    // Setup mock server
    let state = MockManagementState::new();

    let org = create_test_organization("Test Org", OrgStatus::Active);
    let org_id = org.id;
    state.add_organization(org);

    let vault = create_test_vault("Test Vault", org_id);
    let vault_id = vault.id;
    state.add_vault(vault);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Verify vault (should succeed)
    let vault_info =
        verifier.verify_vault(vault_id, org_id).await.expect("Vault verification should succeed");

    assert_eq!(vault_info.id, vault_id);
    assert_eq!(vault_info.organization_id, org_id);
}

#[tokio::test]
async fn test_vault_verification_not_found() {
    // Setup mock server with no vaults
    let state = MockManagementState::new();
    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Try to verify non-existent vault
    let vault_id = generate_snowflake_id();
    let org_id = generate_snowflake_id();
    let result = verifier.verify_vault(vault_id, org_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("not found"));
}

#[tokio::test]
async fn test_vault_verification_account_mismatch() {
    // Setup mock server
    let state = MockManagementState::new();
    let org_id = generate_snowflake_id();
    let vault = create_test_vault("Test Vault", org_id);
    let vault_id = vault.id;
    state.add_vault(vault);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Try to verify vault with wrong organization ID
    let wrong_org_id = generate_snowflake_id();
    let result = verifier.verify_vault(vault_id, wrong_org_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Account mismatch"));
    assert!(err_msg.contains(&org_id.to_string()));
    assert!(err_msg.contains(&wrong_org_id.to_string()));
}

#[tokio::test]
async fn test_vault_verification_caching() {
    // Setup mock server
    let state = MockManagementState::new();
    let org_id = generate_snowflake_id();
    let vault = create_test_vault("Test Vault", org_id);
    let vault_id = vault.id;
    state.add_vault(vault);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // First verification (cache miss)
    let vault_info1 =
        verifier.verify_vault(vault_id, org_id).await.expect("First verification should succeed");

    // Second verification (cache hit)
    let vault_info2 =
        verifier.verify_vault(vault_id, org_id).await.expect("Second verification should succeed");

    assert_eq!(vault_info1.id, vault_info2.id);
    assert_eq!(vault_info1.organization_id, vault_info2.organization_id);
}

#[tokio::test]
async fn test_vault_verification_cache_returns_error_for_mismatch() {
    // Setup mock server
    let state = MockManagementState::new();
    let org_id = generate_snowflake_id();
    let vault = create_test_vault("Test Vault", org_id);
    let vault_id = vault.id;
    state.add_vault(vault);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // First verification with correct organization (populates cache)
    verifier.verify_vault(vault_id, org_id).await.expect("First verification should succeed");

    // Second verification with wrong organization (should fail even from cache)
    let wrong_org_id = generate_snowflake_id();
    let result = verifier.verify_vault(vault_id, wrong_org_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Account mismatch"));
}

// ============================================================================
// Organization Verification Tests
// ============================================================================

#[tokio::test]
async fn test_organization_verification_active() {
    // Setup mock server
    let state = MockManagementState::new();
    let org = create_test_organization("Test Org", OrgStatus::Active);
    let org_id = org.id;
    state.add_organization(org);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Verify organization (should succeed)
    let org_info = verifier
        .verify_organization(org_id)
        .await
        .expect("Organization verification should succeed");

    assert_eq!(org_info.id, org_id);
    assert_eq!(org_info.status, OrgStatus::Active);
}

#[tokio::test]
async fn test_organization_verification_suspended() {
    // Setup mock server
    let state = MockManagementState::new();
    let org = create_test_organization("Suspended Org", OrgStatus::Suspended);
    let org_id = org.id;
    state.add_organization(org);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Try to verify suspended organization
    let result = verifier.verify_organization(org_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("suspended"));
}

#[tokio::test]
async fn test_organization_verification_not_found() {
    // Setup mock server with no organizations
    let state = MockManagementState::new();
    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Try to verify non-existent organization
    let org_id = generate_snowflake_id();
    let result = verifier.verify_organization(org_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("not found"));
}

#[tokio::test]
async fn test_organization_verification_caching() {
    // Setup mock server
    let state = MockManagementState::new();
    let org = create_test_organization("Test Org", OrgStatus::Active);
    let org_id = org.id;
    state.add_organization(org);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // First verification (cache miss)
    let org_info1 =
        verifier.verify_organization(org_id).await.expect("First verification should succeed");

    // Second verification (cache hit)
    let org_info2 =
        verifier.verify_organization(org_id).await.expect("Second verification should succeed");

    assert_eq!(org_info1.id, org_info2.id);
    assert_eq!(org_info1.status, org_info2.status);
}

#[tokio::test]
async fn test_organization_verification_cache_returns_error_for_suspended() {
    // Setup mock server
    let state = MockManagementState::new();
    let org = create_test_organization("Test Org", OrgStatus::Suspended);
    let org_id = org.id;
    state.add_organization(org);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create vault verifier
    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );
    let verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // First verification (populates cache with suspended org)
    let result1 = verifier.verify_organization(org_id).await;
    assert!(result1.is_err());

    // Second verification (should fail from cache)
    let result2 = verifier.verify_organization(org_id).await;
    assert!(result2.is_err());

    let err_msg = result2.unwrap_err().to_string();
    assert!(err_msg.contains("suspended"));
}

// ============================================================================
// End-to-End JWT Authentication Tests
// ============================================================================

#[tokio::test]
async fn test_jwt_authentication_full_flow() {
    // Setup mock server
    let state = MockManagementState::new();

    // Create organization
    let org = create_test_organization("Test Org", OrgStatus::Active);
    let org_id = org.id;
    state.add_organization(org);

    // Create vault
    let vault = create_test_vault("Test Vault", org_id);
    let vault_id = vault.id;
    state.add_vault(vault);

    // Create certificate
    let client_id = generate_snowflake_id();
    let (cert, signing_key) = create_test_certificate(org_id, client_id);
    let cert_id = cert.id;
    state.add_certificate(cert);

    let (base_url, _handle) = start_mock_management_server(state).await;

    // Create management client and caches
    let management_client = Arc::new(
        ManagementClient::new(base_url.clone(), 5000, None).expect("Failed to create management client"),
    );

    let cert_cache = CertificateCache::new(base_url, Duration::from_secs(300), 100)
        .expect("Failed to create certificate cache");

    let vault_verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Generate JWT
    let kid = format!("org-{}-client-{}-cert-{}", org_id, client_id, cert_id);
    let jwt = generate_jwt_with_key(&signing_key, &kid, vault_id, org_id, 300);

    // Step 1: Fetch certificate (for JWT verification)
    let _decoding_key =
        cert_cache.get_decoding_key(&kid).await.expect("Failed to fetch certificate");

    // Step 2: Verify vault ownership
    let vault_info =
        vault_verifier.verify_vault(vault_id, org_id).await.expect("Failed to verify vault");

    assert_eq!(vault_info.id, vault_id);
    assert_eq!(vault_info.organization_id, org_id);

    // Step 3: Verify organization status
    let org_info =
        vault_verifier.verify_organization(org_id).await.expect("Failed to verify organization");

    assert_eq!(org_info.id, org_id);
    assert_eq!(org_info.status, OrgStatus::Active);

    // Verify JWT structure
    assert_eq!(jwt.split('.').count(), 3);
}

#[tokio::test]
async fn test_jwt_authentication_flow_vault_not_found() {
    // Setup mock server with no vaults
    let state = MockManagementState::new();
    let (base_url, _handle) = start_mock_management_server(state).await;

    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );

    let vault_verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Try to verify non-existent vault
    let vault_id = generate_snowflake_id();
    let organization_id = generate_snowflake_id();
    let result = vault_verifier.verify_vault(vault_id, organization_id).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_jwt_authentication_flow_org_suspended() {
    // Setup mock server
    let state = MockManagementState::new();

    // Create suspended organization
    let org = create_test_organization("Suspended Org", OrgStatus::Suspended);
    let org_id = org.id;
    state.add_organization(org);

    // Create vault
    let vault = create_test_vault("Test Vault", org_id);
    state.add_vault(vault);

    let (base_url, _handle) = start_mock_management_server(state).await;

    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );

    let vault_verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Try to verify organization (should fail)
    let result = vault_verifier.verify_organization(org_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("suspended"));
}

#[tokio::test]
async fn test_jwt_authentication_flow_account_mismatch() {
    // Setup mock server
    let state = MockManagementState::new();

    let org = create_test_organization("Test Org", OrgStatus::Active);
    let org_id = org.id;
    state.add_organization(org);

    let vault = create_test_vault("Test Vault", org_id);
    let vault_id = vault.id;
    state.add_vault(vault);

    let (base_url, _handle) = start_mock_management_server(state).await;

    let management_client = Arc::new(
        ManagementClient::new(base_url, 5000, None).expect("Failed to create management client"),
    );

    let vault_verifier = ManagementApiVaultVerifier::new(
        management_client,
        Duration::from_secs(300),
        Duration::from_secs(300),
    );

    // Try to verify vault with wrong organization ID
    let wrong_org_id = generate_snowflake_id();
    let result = vault_verifier.verify_vault(vault_id, wrong_org_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Account mismatch"));
}

// ============================================================================
// Management Client Tests
// ============================================================================

#[tokio::test]
async fn test_management_client_get_organization() {
    let state = MockManagementState::new();
    let org = create_test_organization("Test Org", OrgStatus::Active);
    let org_id = org.id;
    state.add_organization(org);

    let (base_url, _handle) = start_mock_management_server(state).await;

    let client = ManagementClient::new(base_url, 5000, None).expect("Failed to create management client");

    let org_info = client.get_organization(org_id).await.expect("Failed to get organization");

    assert_eq!(org_info.id, org_id);
    assert_eq!(org_info.name, "Test Org");
    assert_eq!(org_info.status, OrgStatus::Active);
}

#[tokio::test]
async fn test_management_client_get_vault() {
    let state = MockManagementState::new();
    let org_id = generate_snowflake_id();
    let vault = create_test_vault("Test Vault", org_id);
    let vault_id = vault.id;
    state.add_vault(vault);

    let (base_url, _handle) = start_mock_management_server(state).await;

    let client = ManagementClient::new(base_url, 5000, None).expect("Failed to create management client");

    let vault_info = client.get_vault(vault_id).await.expect("Failed to get vault");

    assert_eq!(vault_info.id, vault_id);
    assert_eq!(vault_info.organization_id, org_id);
}

#[tokio::test]
async fn test_management_client_timeout() {
    // Create client with very short timeout
    let state = MockManagementState::new();
    let (base_url, _handle) = start_mock_management_server(state).await;

    let client =
        ManagementClient::new(base_url.clone(), 1, None).expect("Failed to create management client");

    // This might timeout or succeed depending on timing, but shouldn't panic
    let _result = client.get_organization(generate_snowflake_id()).await;
    // We don't assert on the result because it's timing-dependent
}
