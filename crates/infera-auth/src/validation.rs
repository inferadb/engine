//! Enhanced JWT claim validation
//!
//! This module provides comprehensive validation for JWT claims, including:
//! - Timestamp validation with configurable clock skew
//! - Maximum token age enforcement
//! - Issuer allowlist/blocklist validation
//! - Audience validation
//! - Algorithm security checks
//!
//! ## Security
//!
//! These validators implement security best practices including:
//! - Clock skew tolerance to handle time synchronization issues
//! - Maximum token age to prevent long-lived tokens
//! - Issuer validation to prevent token confusion attacks
//! - Strict algorithm checks to prevent algorithm substitution attacks

use std::time::{SystemTime, UNIX_EPOCH};

use infera_config::AuthConfig;
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::{error::AuthError, jwt::JwtClaims};

/// Validate all timestamp-related claims with clock skew tolerance
///
/// Checks:
/// - `exp` (expiration) is in the future (with clock skew)
/// - `nbf` (not before) is in the past (with clock skew)
/// - `iat` (issued at) is not too far in the past (max token age)
///
/// # Arguments
///
/// * `claims` - The JWT claims to validate
/// * `config` - Authentication configuration containing clock skew and max age settings
///
/// # Errors
///
/// Returns an error if any timestamp validation fails
pub fn validate_timestamp_claims(claims: &JwtClaims, config: &AuthConfig) -> Result<(), AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::InvalidTokenFormat("System time is before Unix epoch".to_string()))?
        .as_secs();

    let clock_skew = config.clock_skew_seconds.unwrap_or(60);
    let max_age = config.max_token_age_seconds.unwrap_or(86400); // 24 hours default

    // Check expiration with clock skew tolerance
    if claims.exp + clock_skew <= now {
        return Err(AuthError::TokenExpired);
    }

    // Check not-before with clock skew tolerance
    if let Some(nbf) = claims.nbf {
        if nbf > now + clock_skew {
            return Err(AuthError::TokenNotYetValid);
        }
    }

    // Check issued-at is not in the future (with clock skew)
    if claims.iat > now + clock_skew {
        return Err(AuthError::InvalidTokenFormat("iat claim is in the future".into()));
    }

    // Check token age (prevent very old tokens from being used)
    let token_age = now.saturating_sub(claims.iat);
    if token_age > max_age {
        warn!(
            token_age = %token_age,
            max_age = %max_age,
            "Token exceeds maximum age"
        );
        return Err(AuthError::TokenTooOld);
    }

    Ok(())
}

/// Validate issuer against allowlist/blocklist
///
/// # Arguments
///
/// * `iss` - The issuer claim from the JWT
/// * `config` - Authentication configuration containing issuer lists
///
/// # Errors
///
/// Returns an error if:
/// - Issuer is empty
/// - Issuer is in the blocklist
/// - Allowlist is configured and issuer is not in it
pub fn validate_issuer(iss: &str, config: &AuthConfig) -> Result<(), AuthError> {
    if iss.is_empty() {
        return Err(AuthError::InvalidIssuer("Issuer cannot be empty".into()));
    }

    // Check blocklist first
    if let Some(ref blocklist) = config.issuer_blocklist {
        if blocklist.iter().any(|blocked| blocked == iss) {
            warn!(issuer = %iss, "Issuer is blocked");
            return Err(AuthError::InvalidIssuer(format!("Issuer '{}' is blocked", iss)));
        }
    }

    // Check allowlist if configured
    if let Some(ref allowlist) = config.issuer_allowlist {
        if !allowlist.iter().any(|allowed| allowed == iss) {
            warn!(issuer = %iss, "Issuer not in allowlist");
            return Err(AuthError::InvalidIssuer(format!("Issuer '{}' is not in allowlist", iss)));
        }
    }

    Ok(())
}

/// Validate audience claim
///
/// # Arguments
///
/// * `aud` - The audience claim from the JWT
/// * `config` - Authentication configuration containing allowed audiences
///
/// # Errors
///
/// Returns an error if:
/// - Audience enforcement is enabled and audience doesn't match
/// - Audience is not in the allowed audiences list
pub fn validate_audience(aud: &str, config: &AuthConfig) -> Result<(), AuthError> {
    // If enforcement is disabled, skip validation
    if !config.enforce_audience {
        return Ok(());
    }

    // Check against allowed audiences
    if config.allowed_audiences.is_empty() {
        warn!("No allowed audiences configured but enforcement is enabled");
        return Err(AuthError::InvalidAudience("No allowed audiences configured".into()));
    }

    if !config.allowed_audiences.iter().any(|allowed| allowed == aud) {
        warn!(audience = %aud, "Audience not in allowed list");
        return Err(AuthError::InvalidAudience(format!("Audience '{}' is not allowed", aud)));
    }

    Ok(())
}

/// Validate JWT algorithm against security policies
///
/// This function enforces strict algorithm security:
/// - ALWAYS rejects symmetric algorithms (HS256, HS384, HS512)
/// - ALWAYS rejects "none" algorithm
/// - Only accepts algorithms in the configured allowed list
///
/// # Arguments
///
/// * `alg` - The algorithm from the JWT header
/// * `config` - Authentication configuration containing accepted algorithms
///
/// # Errors
///
/// Returns an error if:
/// - Algorithm is symmetric (HS256, HS384, HS512)
/// - Algorithm is "none"
/// - Algorithm is not in the accepted algorithms list
pub fn validate_algorithm(alg: &str, config: &AuthConfig) -> Result<(), AuthError> {
    // Hardcoded blocklist - never accept these (using constant-time comparison)
    const FORBIDDEN: &[&str] = &["none", "HS256", "HS384", "HS512"];

    if FORBIDDEN.iter().any(|forbidden| alg.as_bytes().ct_eq(forbidden.as_bytes()).into()) {
        warn!(algorithm = %alg, "Forbidden algorithm rejected");
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is forbidden for security reasons (symmetric or none)",
            alg
        )));
    }

    // Check against accepted algorithms
    if config.accepted_algorithms.is_empty() {
        warn!("No accepted algorithms configured");
        return Err(AuthError::UnsupportedAlgorithm("No accepted algorithms configured".into()));
    }

    if !config
        .accepted_algorithms
        .iter()
        .any(|accepted| accepted.as_bytes().ct_eq(alg.as_bytes()).into())
    {
        warn!(algorithm = %alg, "Algorithm not in accepted list");
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not in accepted list",
            alg
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::jwt::JwtClaims;

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn default_config() -> AuthConfig {
        AuthConfig {
            enabled: true,
            jwks_url: "https://example.com".into(),
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
            jwks_base_url: "https://example.com".into(),
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
        }
    }

    fn test_claims(exp: u64, iat: u64, nbf: Option<u64>) -> JwtClaims {
        JwtClaims {
            iss: "tenant:acme".into(),
            sub: "test".into(),
            aud: "inferadb".into(),
            exp,
            iat,
            nbf,
            jti: Some("test-jti".into()),
            scope: "inferadb.check".into(),
            tenant_id: None,
            vault: None,
            account: None,
        }
    }

    #[test]
    fn test_validate_timestamp_claims_valid() {
        let config = default_config();
        let claims = test_claims(now() + 3600, now() - 60, None);

        assert!(validate_timestamp_claims(&claims, &config).is_ok());
    }

    #[test]
    fn test_validate_timestamp_claims_expired() {
        let config = default_config();
        let claims = test_claims(now() - 120, now() - 3600, None); // Expired 2 minutes ago

        let result = validate_timestamp_claims(&claims, &config);
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_validate_timestamp_claims_expired_within_skew() {
        let config = default_config();
        let claims = test_claims(now() - 30, now() - 3600, None); // Expired 30 seconds ago

        // Should succeed because clock skew is 60 seconds
        assert!(validate_timestamp_claims(&claims, &config).is_ok());
    }

    #[test]
    fn test_validate_timestamp_claims_not_yet_valid() {
        let config = default_config();
        let claims = test_claims(now() + 3600, now(), Some(now() + 120)); // nbf 2 minutes in future

        let result = validate_timestamp_claims(&claims, &config);
        assert!(matches!(result, Err(AuthError::TokenNotYetValid)));
    }

    #[test]
    fn test_validate_timestamp_claims_iat_future() {
        let config = default_config();
        let claims = test_claims(now() + 3600, now() + 120, None); // iat 2 minutes in future

        let result = validate_timestamp_claims(&claims, &config);
        assert!(matches!(result, Err(AuthError::InvalidTokenFormat(_))));
    }

    #[test]
    fn test_validate_timestamp_claims_too_old() {
        let config = default_config();
        let claims = test_claims(now() + 3600, now() - 86400 - 3600, None); // iat 25 hours ago

        let result = validate_timestamp_claims(&claims, &config);
        assert!(matches!(result, Err(AuthError::TokenTooOld)));
    }

    #[test]
    fn test_validate_issuer_valid() {
        let config = default_config();
        assert!(validate_issuer("tenant:acme", &config).is_ok());
    }

    #[test]
    fn test_validate_issuer_empty() {
        let config = default_config();
        let result = validate_issuer("", &config);
        assert!(matches!(result, Err(AuthError::InvalidIssuer(_))));
    }

    #[test]
    fn test_validate_issuer_allowlist() {
        let mut config = default_config();
        config.issuer_allowlist = Some(vec!["tenant:acme".into(), "tenant:globex".into()]);

        assert!(validate_issuer("tenant:acme", &config).is_ok());
        assert!(validate_issuer("tenant:globex", &config).is_ok());

        let result = validate_issuer("tenant:evil", &config);
        assert!(matches!(result, Err(AuthError::InvalidIssuer(_))));
    }

    #[test]
    fn test_validate_issuer_blocklist() {
        let mut config = default_config();
        config.issuer_blocklist = Some(vec!["tenant:evil".into(), "tenant:banned".into()]);

        assert!(validate_issuer("tenant:acme", &config).is_ok());

        let result = validate_issuer("tenant:evil", &config);
        assert!(matches!(result, Err(AuthError::InvalidIssuer(_))));
    }

    #[test]
    fn test_validate_audience_valid() {
        let config = default_config();
        assert!(validate_audience("inferadb", &config).is_ok());
    }

    #[test]
    fn test_validate_audience_invalid() {
        let config = default_config();
        let result = validate_audience("wrong-audience", &config);
        assert!(matches!(result, Err(AuthError::InvalidAudience(_))));
    }

    #[test]
    fn test_validate_audience_disabled() {
        let mut config = default_config();
        config.enforce_audience = false;

        // Should accept any audience when enforcement is disabled
        assert!(validate_audience("any-audience", &config).is_ok());
    }

    #[test]
    fn test_validate_algorithm_asymmetric() {
        let config = default_config();
        assert!(validate_algorithm("EdDSA", &config).is_ok());
        assert!(validate_algorithm("RS256", &config).is_ok());
    }

    #[test]
    fn test_validate_algorithm_symmetric_rejected() {
        let config = default_config();
        assert!(validate_algorithm("HS256", &config).is_err());
        assert!(validate_algorithm("HS384", &config).is_err());
        assert!(validate_algorithm("HS512", &config).is_err());
    }

    #[test]
    fn test_validate_algorithm_none_rejected() {
        let config = default_config();
        let result = validate_algorithm("none", &config);
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_validate_algorithm_not_in_list() {
        let config = default_config();
        let result = validate_algorithm("ES256", &config);
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_validate_algorithm_empty_list() {
        let mut config = default_config();
        config.accepted_algorithms = vec![];

        let result = validate_algorithm("EdDSA", &config);
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm(_))));
    }
}
