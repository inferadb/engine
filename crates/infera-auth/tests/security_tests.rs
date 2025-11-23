//! Comprehensive security integration tests for authentication
//!
//! These tests verify that all security best practices are enforced:
//! - Replay protection
//! - Algorithm security (rejecting symmetric algorithms)
//! - Clock skew tolerance
//! - Maximum token age
//! - Issuer validation
//! - Audience validation

use std::time::{SystemTime, UNIX_EPOCH};

use infera_auth::{
    error::AuthError,
    jwt::JwtClaims,
    replay::{InMemoryReplayProtection, ReplayProtection},
    validation::{
        validate_algorithm, validate_audience, validate_issuer, validate_timestamp_claims,
    },
};
use infera_config::AuthConfig;

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
        aud: "inferadb".into(),
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
        enabled: true,
        jwks_url: "https://auth.example.com/.well-known/jwks.json".into(),
        accepted_algorithms: vec!["EdDSA".into(), "RS256".into()],
        enforce_audience: true,
        allowed_audiences: vec!["inferadb".into()],
        enforce_scopes: true,
        required_scopes: vec!["inferadb.check".into()],
        clock_skew_seconds: Some(60),
        max_token_age_seconds: Some(86400),
        issuer_allowlist: None,
        issuer_blocklist: None,
        require_jti: false,
        oauth_enabled: false,
        oidc_discovery_url: None,
        oidc_client_id: None,
        oidc_client_secret: None,
        introspection_url: None,
        redis_url: None,
        jwks_cache_ttl: 300,
        jwks_base_url: "https://auth.example.com".into(),
        replay_protection: false,
        oauth_introspection_endpoint: None,
        oauth_introspection_client_id: None,
        oauth_introspection_client_secret: None,
        oidc_discovery_cache_ttl: 86400,
        introspection_cache_ttl: 60,
        internal_jwks_path: None,
        internal_jwks_env: None,
        internal_issuer: "https://internal.inferadb.com".into(),
        internal_audience: "https://api.inferadb.com/internal".into(),
        audience: "inferadb".into(),
        management_api_url: "https://api.example.com".into(),
        management_api_timeout_ms: 5000,
        management_cache_ttl_seconds: 300,
        cert_cache_ttl_seconds: 300,
        management_verify_vault_ownership: false,
        management_verify_org_status: false,
        server_identity_private_key: None,
        server_identity_kid: "server-default".into(),
        server_id: "default".into(),
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
    let config = default_config();

    // HS256, HS384, HS512 should all be rejected
    assert!(validate_algorithm("HS256", &config.accepted_algorithms).is_err());
    assert!(validate_algorithm("HS384", &config.accepted_algorithms).is_err());
    assert!(validate_algorithm("HS512", &config.accepted_algorithms).is_err());
}

#[test]
fn test_none_algorithm_rejected() {
    let config = default_config();

    let result = validate_algorithm("none", &config.accepted_algorithms);
    assert!(
        matches!(result, Err(AuthError::UnsupportedAlgorithm(_))),
        "Algorithm 'none' should be rejected"
    );
}

#[test]
fn test_accepted_algorithms_allowed() {
    let config = default_config();

    assert!(validate_algorithm("EdDSA", &config.accepted_algorithms).is_ok());
    assert!(validate_algorithm("RS256", &config.accepted_algorithms).is_ok());
}

#[test]
fn test_unlisted_asymmetric_algorithm_rejected() {
    let config = default_config();

    // ES256 is asymmetric but not in our accepted list
    let result = validate_algorithm("ES256", &config.accepted_algorithms);
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
// Issuer Validation Tests
// ============================================================================

#[test]
fn test_issuer_in_allowlist_accepted() {
    let mut config = default_config();
    config.issuer_allowlist = Some(vec!["tenant:acme".into(), "tenant:globex".into()]);

    assert!(validate_issuer("tenant:acme", &config).is_ok());
    assert!(validate_issuer("tenant:globex", &config).is_ok());
}

#[test]
fn test_issuer_not_in_allowlist_rejected() {
    let mut config = default_config();
    config.issuer_allowlist = Some(vec!["tenant:acme".into()]);

    let result = validate_issuer("tenant:evil", &config);
    assert!(
        matches!(result, Err(AuthError::InvalidIssuer(_))),
        "Issuer not in allowlist should be rejected"
    );
}

#[test]
fn test_issuer_in_blocklist_rejected() {
    let mut config = default_config();
    config.issuer_blocklist = Some(vec!["tenant:evil".into(), "tenant:banned".into()]);

    let result = validate_issuer("tenant:evil", &config);
    assert!(
        matches!(result, Err(AuthError::InvalidIssuer(_))),
        "Issuer in blocklist should be rejected"
    );
}

#[test]
fn test_empty_issuer_rejected() {
    let config = default_config();

    let result = validate_issuer("", &config);
    assert!(matches!(result, Err(AuthError::InvalidIssuer(_))), "Empty issuer should be rejected");
}

// ============================================================================
// Audience Validation Tests
// ============================================================================

#[test]
fn test_audience_in_allowed_list_accepted() {
    let config = default_config();

    assert!(validate_audience("inferadb", &config).is_ok());
}

#[test]
fn test_audience_not_in_allowed_list_rejected() {
    let config = default_config();

    let result = validate_audience("wrong-audience", &config);
    assert!(
        matches!(result, Err(AuthError::InvalidAudience(_))),
        "Audience not in allowed list should be rejected"
    );
}

#[test]
fn test_audience_validation_disabled() {
    let mut config = default_config();
    config.enforce_audience = false;

    // Any audience should be accepted when enforcement is disabled
    assert!(validate_audience("any-audience", &config).is_ok());
    assert!(validate_audience("wrong-audience", &config).is_ok());
}

// ============================================================================
// Configuration Validation Tests
// ============================================================================

#[test]
fn test_config_rejects_symmetric_algorithms() {
    let mut config = default_config();
    config.accepted_algorithms = vec!["HS256".into()];

    let result = config.validate();
    assert!(result.is_err(), "Config with HS256 should be rejected");
}

#[test]
fn test_config_rejects_none_algorithm() {
    let mut config = default_config();
    config.accepted_algorithms = vec!["none".into()];

    let result = config.validate();
    assert!(result.is_err(), "Config with 'none' should be rejected");
}

#[test]
fn test_config_rejects_empty_algorithms() {
    let mut config = default_config();
    config.accepted_algorithms = vec![];

    let result = config.validate();
    assert!(result.is_err(), "Config with empty algorithms should be rejected");
}

#[test]
fn test_config_validates_with_asymmetric_algorithms() {
    let config = default_config();

    let result = config.validate();
    assert!(result.is_ok(), "Config with only asymmetric algorithms should be valid");
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

    // Validate issuer
    assert!(validate_issuer(&claims.iss, &config).is_ok());

    // Validate audience
    assert!(validate_audience(&claims.aud, &config).is_ok());

    // Validate algorithm
    assert!(validate_algorithm("EdDSA", &config.accepted_algorithms).is_ok());

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
