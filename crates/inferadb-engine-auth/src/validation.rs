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

use inferadb_engine_config::TokenConfig;
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::{error::AuthError, jwt::JwtClaims};

/// Forbidden JWT algorithms that are never accepted for security reasons
///
/// These algorithms are blocked because:
/// - `none`: No signature verification (trivially bypassable)
/// - `HS256`, `HS384`, `HS512`: Symmetric algorithms (shared secret vulnerability)
///
/// Only asymmetric algorithms (EdDSA, RS256) are allowed.
pub const FORBIDDEN_ALGORITHMS: &[&str] = &["none", "HS256", "HS384", "HS512"];

/// Accepted JWT algorithms
///
/// These are the only algorithms accepted:
/// - `EdDSA`: Ed25519 signatures (recommended, fastest, most secure)
/// - `RS256`: RSA-SHA256 signatures (legacy support)
///
/// This list is intentionally not configurable to ensure consistent security
/// across all deployments. The management API uses EdDSA exclusively.
pub const ACCEPTED_ALGORITHMS: &[&str] = &["EdDSA", "RS256"];

/// Required JWT audience for InferaDB Server API
///
/// Per RFC 8725 (JWT Best Current Practices), the audience claim identifies
/// the intended recipient of the token - in this case, the InferaDB Server API.
///
/// This value is hardcoded to ensure consistent security across all deployments
/// and to match the audience set by the Management API when generating tokens.
pub const REQUIRED_AUDIENCE: &str = "https://api.inferadb.com";

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
pub fn validate_timestamp_claims(
    claims: &JwtClaims,
    config: &TokenConfig,
) -> Result<(), AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::InvalidTokenFormat("System time is before Unix epoch".to_string()))?
        .as_secs();

    let clock_skew = config.clock_skew.unwrap_or(60);
    let max_age = config.max_age.unwrap_or(86400); // 24 hours default

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

/// Validate audience claim against the required InferaDB Server API audience
///
/// Audience validation is always enforced - tokens must have an audience
/// that matches the hardcoded REQUIRED_AUDIENCE constant.
///
/// # Arguments
///
/// * `aud` - The audience claim from the JWT
///
/// # Errors
///
/// Returns an error if the audience doesn't match REQUIRED_AUDIENCE
pub fn validate_audience(aud: &str) -> Result<(), AuthError> {
    if aud != REQUIRED_AUDIENCE {
        warn!(
            audience = %aud,
            expected = %REQUIRED_AUDIENCE,
            "Audience mismatch"
        );
        return Err(AuthError::InvalidAudience(format!(
            "Audience '{}' does not match required audience '{}'",
            aud, REQUIRED_AUDIENCE
        )));
    }

    Ok(())
}

/// Validate JWT algorithm against security policies
///
/// This function enforces strict algorithm security:
/// - ALWAYS rejects symmetric algorithms (HS256, HS384, HS512)
/// - ALWAYS rejects "none" algorithm
/// - Only accepts EdDSA and RS256
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `alg` - The algorithm from the JWT header
///
/// # Errors
///
/// Returns an error if:
/// - Algorithm is symmetric (HS256, HS384, HS512)
/// - Algorithm is "none"
/// - Algorithm is not EdDSA or RS256
///
/// # Examples
///
/// ```rust
/// use inferadb_engine_auth::validation::validate_algorithm;
///
/// // EdDSA is accepted
/// let result = validate_algorithm("EdDSA");
/// assert!(result.is_ok());
///
/// // RS256 is accepted
/// let result = validate_algorithm("RS256");
/// assert!(result.is_ok());
///
/// // Symmetric algorithm rejected
/// let result = validate_algorithm("HS256");
/// assert!(result.is_err());
/// ```
pub fn validate_algorithm(alg: &str) -> Result<(), AuthError> {
    // Check against forbidden algorithms using constant-time comparison
    if FORBIDDEN_ALGORITHMS
        .iter()
        .any(|forbidden| alg.as_bytes().ct_eq(forbidden.as_bytes()).into())
    {
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not allowed for security reasons",
            alg
        )));
    }

    // Check if in accepted list (using constant-time comparison)
    if !ACCEPTED_ALGORITHMS.iter().any(|a| a.as_bytes().ct_eq(alg.as_bytes()).into()) {
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not in accepted list (only EdDSA and RS256 are supported)",
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

    fn default_config() -> TokenConfig {
        TokenConfig { cache_ttl: 300, clock_skew: Some(60), max_age: Some(86400) }
    }

    fn test_claims(exp: u64, iat: u64, nbf: Option<u64>) -> JwtClaims {
        JwtClaims {
            iss: "tenant:acme".into(),
            sub: "test".into(),
            aud: REQUIRED_AUDIENCE.into(),
            exp,
            iat,
            nbf,
            jti: Some("test-jti".into()),
            scope: "inferadb.check".into(),
            vault_id: None,
            org_id: None,
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
    fn test_validate_audience_valid() {
        assert!(validate_audience(REQUIRED_AUDIENCE).is_ok());
    }

    #[test]
    fn test_validate_audience_invalid() {
        let result = validate_audience("wrong-audience");
        assert!(matches!(result, Err(AuthError::InvalidAudience(_))));
    }

    #[test]
    fn test_validate_audience_rejects_old_endpoint_style() {
        // The old endpoint-style audience is no longer valid
        let result = validate_audience("https://api.inferadb.com/evaluate");
        assert!(matches!(result, Err(AuthError::InvalidAudience(_))));
    }

    #[test]
    fn test_required_audience_constant() {
        // Verify the constant is set correctly
        assert_eq!(REQUIRED_AUDIENCE, "https://api.inferadb.com");
    }

    #[test]
    fn test_validate_algorithm_asymmetric() {
        assert!(validate_algorithm("EdDSA").is_ok());
        assert!(validate_algorithm("RS256").is_ok());
    }

    #[test]
    fn test_validate_algorithm_symmetric_rejected() {
        assert!(validate_algorithm("HS256").is_err());
        assert!(validate_algorithm("HS384").is_err());
        assert!(validate_algorithm("HS512").is_err());
    }

    #[test]
    fn test_validate_algorithm_none_rejected() {
        let result = validate_algorithm("none");
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_validate_algorithm_not_in_list() {
        // ES256 is not in ACCEPTED_ALGORITHMS
        let result = validate_algorithm("ES256");
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_forbidden_algorithms_constant() {
        // Verify the FORBIDDEN_ALGORITHMS constant is correctly defined
        assert_eq!(FORBIDDEN_ALGORITHMS.len(), 4);
        assert!(FORBIDDEN_ALGORITHMS.contains(&"none"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS256"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS384"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS512"));
    }

    #[test]
    fn test_accepted_algorithms_constant() {
        // Verify the ACCEPTED_ALGORITHMS constant is correctly defined
        assert_eq!(ACCEPTED_ALGORITHMS.len(), 2);
        assert!(ACCEPTED_ALGORITHMS.contains(&"EdDSA"));
        assert!(ACCEPTED_ALGORITHMS.contains(&"RS256"));
    }
}
