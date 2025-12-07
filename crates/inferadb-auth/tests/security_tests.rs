//! Comprehensive security integration tests for authentication
//!
//! These tests verify that all security best practices are enforced:
//! - Replay protection
//! - Algorithm security (rejecting symmetric algorithms)
//! - Clock skew tolerance
//! - Maximum token age
//! - Audience validation

use std::time::{SystemTime, UNIX_EPOCH};

use inferadb_auth::{
    error::AuthError,
    jwt::JwtClaims,
    replay::{InMemoryReplayProtection, ReplayProtection},
    validation::{validate_algorithm, validate_audience, validate_timestamp_claims, REQUIRED_AUDIENCE},
};
use inferadb_config::AuthConfig;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn future_timestamp(offset_secs: u64) -> u64 {
    now() + offset_secs
}

fn past_timestamp(offset_secs: u64) -> u64 {
    now().saturating_sub(offset_secs)
}

fn test_claims(exp: u64, iat: u64, nbf: Option<u64>, jti: Option<String>) -> JwtClaims {
    JwtClaims {
        iss: "tenant:acme".into(),
        sub: "test-user".into(),
        aud: REQUIRED_AUDIENCE.into(),
        exp,
        iat,
        nbf,
        jti,
        scope: "inferadb.check inferadb.write".into(),
        vault_id: None,
        org_id: None,
    }
}

fn default_config() -> AuthConfig {
    AuthConfig {
        jwks_url: "https://auth.example.com/.well-known/jwks.json".into(),
        clock_skew_seconds: Some(60),
        max_token_age_seconds: Some(86400),
        require_jti: false,
        oauth_enabled: false,
        oidc_discovery_url: None,
        oidc_client_id: None,
        oidc_client_secret: None,
        redis_url: None,
        jwks_cache_ttl: 300,
        replay_protection: false,
        oidc_discovery_cache_ttl: 86400,
        management_api_timeout_ms: 5000,
        management_cache_ttl: 300,
        cert_cache_ttl: 300,
        management_verify_vault_ownership: false,
        management_verify_org_status: false,
    }
}

// ============================================================================
// Replay Protection Tests
// ============================================================================

#[tokio::test]
async fn test_replay_protection_first_use_succeeds() {
    let replay = InMemoryReplayProtection::new();
    let exp = future_timestamp(3600);
    let jti = "unique-jti-001";

    let is_new = replay.check_and_mark(jti, exp).await.unwrap();
    assert!(is_new, "First use of JTI should return true");
}

#[tokio::test]
async fn test_replay_protection_second_use_fails() {
    let replay = InMemoryReplayProtection::new();
    let exp = future_timestamp(3600);
    let jti = "unique-jti-002";

    // First use
    let is_new = replay.check_and_mark(jti, exp).await.unwrap();
    assert!(is_new, "First use should return true");

    // Second use (replay)
    let is_replay = replay.check_and_mark(jti, exp).await.unwrap();
    assert!(!is_replay, "Second use should return false (replay detected)");
}

#[tokio::test]
async fn test_replay_protection_expired_token_rejected() {
    let replay = InMemoryReplayProtection::new();
    let exp = past_timestamp(10); // Expired 10 seconds ago
    let jti = "expired-jti-001";

    let result = replay.check_and_mark(jti, exp).await;
    assert!(matches!(result, Err(AuthError::TokenExpired)), "Expired token should be rejected");
}

#[tokio::test]
async fn test_replay_protection_different_jtis_independent() {
    let replay = InMemoryReplayProtection::new();
    let exp = future_timestamp(3600);

    let jti1 = "jti-001";
    let jti2 = "jti-002";

    // First JTI
    assert!(replay.check_and_mark(jti1, exp).await.unwrap());

    // Second JTI (different)
    assert!(replay.check_and_mark(jti2, exp).await.unwrap());

    // Replay first JTI
    assert!(!replay.check_and_mark(jti1, exp).await.unwrap());

    // Replay second JTI
    assert!(!replay.check_and_mark(jti2, exp).await.unwrap());
}

// ============================================================================
// Algorithm Security Tests
// ============================================================================

#[test]
fn test_symmetric_algorithms_rejected() {
    // HS256, HS384, HS512 should all be rejected
    assert!(validate_algorithm("HS256").is_err());
    assert!(validate_algorithm("HS384").is_err());
    assert!(validate_algorithm("HS512").is_err());
}

#[test]
fn test_none_algorithm_rejected() {
    let result = validate_algorithm("none");
    assert!(
        matches!(result, Err(AuthError::UnsupportedAlgorithm(_))),
        "Algorithm 'none' should be rejected"
    );
}

#[test]
fn test_accepted_algorithms_allowed() {
    assert!(validate_algorithm("EdDSA").is_ok());
    assert!(validate_algorithm("RS256").is_ok());
}

#[test]
fn test_unlisted_asymmetric_algorithm_rejected() {
    let result = validate_algorithm("ES256");
    assert!(
        matches!(result, Err(AuthError::UnsupportedAlgorithm(_))),
        "Unlisted algorithm should be rejected"
    );
}

// ============================================================================
// Clock Skew Tolerance Tests
// ============================================================================

#[test]
fn test_expired_token_within_skew_accepted() {
    let config = default_config();
    // Token expired 30 seconds ago, but clock skew is 60 seconds
    let claims = test_claims(past_timestamp(30), past_timestamp(3600), None, None);

    let result = validate_timestamp_claims(&claims, &config);
    assert!(result.is_ok(), "Token within clock skew should be accepted");
}

#[test]
fn test_expired_token_outside_skew_rejected() {
    let config = default_config();
    // Token expired 120 seconds ago, outside 60 second clock skew
    let claims = test_claims(past_timestamp(120), past_timestamp(3600), None, None);

    let result = validate_timestamp_claims(&claims, &config);
    assert!(
        matches!(result, Err(AuthError::TokenExpired)),
        "Token outside clock skew should be rejected"
    );
}

#[test]
fn test_nbf_within_skew_accepted() {
    let config = default_config();
    // nbf is 30 seconds in future, but clock skew is 60 seconds
    let claims = test_claims(future_timestamp(3600), now(), Some(future_timestamp(30)), None);

    let result = validate_timestamp_claims(&claims, &config);
    assert!(result.is_ok(), "Token with nbf within clock skew should be accepted");
}

#[test]
fn test_nbf_outside_skew_rejected() {
    let config = default_config();
    // nbf is 120 seconds in future, outside 60 second clock skew
    let claims = test_claims(future_timestamp(3600), now(), Some(future_timestamp(120)), None);

    let result = validate_timestamp_claims(&claims, &config);
    assert!(
        matches!(result, Err(AuthError::TokenNotYetValid)),
        "Token with nbf outside clock skew should be rejected"
    );
}

// ============================================================================
// Maximum Token Age Tests
// ============================================================================

#[test]
fn test_token_within_max_age_accepted() {
    let config = default_config();
    // Token issued 12 hours ago (within 24 hour max age)
    let claims = test_claims(future_timestamp(3600), past_timestamp(43200), None, None);

    let result = validate_timestamp_claims(&claims, &config);
    assert!(result.is_ok(), "Token within max age should be accepted");
}

#[test]
fn test_token_exceeds_max_age_rejected() {
    let config = default_config();
    // Token issued 48 hours ago (exceeds 24 hour max age)
    let claims = test_claims(future_timestamp(3600), past_timestamp(172800), None, None);

    let result = validate_timestamp_claims(&claims, &config);
    assert!(
        matches!(result, Err(AuthError::TokenTooOld)),
        "Token exceeding max age should be rejected"
    );
}

#[test]
fn test_iat_in_future_rejected() {
    let config = default_config();
    // iat is 120 seconds in future (outside clock skew)
    let claims = test_claims(future_timestamp(3600), future_timestamp(120), None, None);

    let result = validate_timestamp_claims(&claims, &config);
    assert!(
        matches!(result, Err(AuthError::InvalidTokenFormat(_))),
        "Token with future iat should be rejected"
    );
}

// ============================================================================
// Audience Validation Tests
// ============================================================================

#[test]
fn test_audience_matches_required() {
    assert!(validate_audience(REQUIRED_AUDIENCE).is_ok());
}

#[test]
fn test_audience_mismatch_rejected() {
    let result = validate_audience("wrong-audience");
    assert!(
        matches!(result, Err(AuthError::InvalidAudience(_))),
        "Audience not matching REQUIRED_AUDIENCE should be rejected"
    );
}

// ============================================================================
// Configuration Validation Tests
// ============================================================================

#[test]
fn test_config_validates_successfully() {
    let config = default_config();

    let result = config.validate();
    assert!(result.is_ok(), "Default config should be valid");
}

// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_full_validation_flow_success() {
    let config = default_config();
    let claims = test_claims(future_timestamp(3600), now(), None, Some("unique-jti-100".into()));

    // Validate timestamps
    assert!(validate_timestamp_claims(&claims, &config).is_ok());

    // Validate audience
    assert!(validate_audience(&claims.aud).is_ok());

    // Validate algorithm
    assert!(validate_algorithm("EdDSA").is_ok());

    // Check replay protection
    let replay = InMemoryReplayProtection::new();
    let jti = claims.jti.as_ref().unwrap();
    assert!(replay.check_and_mark(jti, claims.exp).await.unwrap());
}

#[tokio::test]
async fn test_full_validation_flow_replay_detected() {
    let _config = default_config();
    let claims = test_claims(future_timestamp(3600), now(), None, Some("unique-jti-101".into()));

    let replay = InMemoryReplayProtection::new();
    let jti = claims.jti.as_ref().unwrap();

    // First validation succeeds
    assert!(replay.check_and_mark(jti, claims.exp).await.unwrap());

    // Second validation detects replay
    assert!(!replay.check_and_mark(jti, claims.exp).await.unwrap());
}
