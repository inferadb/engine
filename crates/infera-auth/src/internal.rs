//! Internal service JWT authentication
//!
//! This module handles authentication for internal services (Control Plane → PDP).
//! Internal services authenticate using JWTs signed with keys from a local JWKS.
//!
//! ## Usage
//!
//! ```ignore
//! use infera_auth::internal::{InternalJwks, InternalJwksLoader};
//!
//! // Load JWKS from file
//! let jwks = InternalJwks::from_file("/path/to/jwks.json")?;
//!
//! // Or from environment variable
//! let jwks = InternalJwks::from_env("INTERNAL_JWKS")?;
//!
//! // Create loader
//! let loader = InternalJwksLoader::new(jwks);
//!
//! // Validate JWT
//! let auth_ctx = validate_internal_jwt(token, &loader, &config)?;
//! ```

use crate::context::{AuthContext, AuthMethod};
use crate::error::AuthError;
use crate::jwks_cache::Jwk;
use crate::jwt::JwtClaims;
use jsonwebtoken::{decode, decode_header, Validation};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Internal JWKS structure for local key storage
///
/// This structure contains public keys used to verify JWTs from internal services.
/// Keys are stored locally (file or environment variable) rather than fetched from
/// a remote endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalJwks {
    /// Issuer identifier (e.g., "https://internal.inferadb.com")
    pub issuer: String,

    /// Expected audience (e.g., "https://api.inferadb.com/internal")
    pub audience: String,

    /// Public keys for signature verification
    pub keys: Vec<Jwk>,
}

impl InternalJwks {
    /// Create a new InternalJwks with validation
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - No keys are present
    /// - Any key is missing required fields
    /// - Issuer is empty
    pub fn new(issuer: String, audience: String, keys: Vec<Jwk>) -> Result<Self, AuthError> {
        let jwks = Self {
            issuer,
            audience,
            keys,
        };

        jwks.validate()?;
        Ok(jwks)
    }

    /// Validate the JWKS structure
    fn validate(&self) -> Result<(), AuthError> {
        // At least one key must be present
        if self.keys.is_empty() {
            return Err(AuthError::JwksError(
                "Internal JWKS must contain at least one key".to_string(),
            ));
        }

        // All keys must have kid
        for key in &self.keys {
            if key.kid.is_empty() {
                return Err(AuthError::JwksError(
                    "All keys in internal JWKS must have a 'kid' field".to_string(),
                ));
            }
        }

        // All keys must have valid alg
        for key in &self.keys {
            if key.alg.is_none() || key.alg.as_ref().unwrap().is_empty() {
                return Err(AuthError::JwksError(
                    "All keys in internal JWKS must have a non-empty 'alg' field".to_string(),
                ));
            }
        }

        // Issuer must be non-empty
        if self.issuer.is_empty() {
            return Err(AuthError::JwksError(
                "Internal JWKS issuer cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    /// Load JWKS from a file
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be read
    /// - File contains invalid JSON
    /// - JWKS structure is invalid
    pub fn from_file(path: &Path) -> Result<Self, AuthError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| AuthError::JwksError(format!("Failed to read JWKS file: {}", e)))?;

        let jwks: InternalJwks = serde_json::from_str(&contents)
            .map_err(|e| AuthError::JwksError(format!("Failed to parse JWKS JSON: {}", e)))?;

        jwks.validate()?;

        // Check file permissions (warn if world-readable)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path) {
                let permissions = metadata.permissions();
                let mode = permissions.mode();
                // Check if world-readable (o+r)
                if mode & 0o004 != 0 {
                    tracing::warn!(
                        path = ?path,
                        "Internal JWKS file is world-readable - consider restricting permissions to 0600"
                    );
                }
            }
        }

        Ok(jwks)
    }

    /// Load JWKS from environment variable
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Environment variable not set
    /// - Value contains invalid JSON
    /// - JWKS structure is invalid
    pub fn from_env(var_name: &str) -> Result<Self, AuthError> {
        let contents = std::env::var(var_name).map_err(|_| {
            AuthError::JwksError(format!("Environment variable '{}' not set", var_name))
        })?;

        let jwks: InternalJwks = serde_json::from_str(&contents).map_err(|e| {
            AuthError::JwksError(format!(
                "Failed to parse JWKS JSON from env var '{}': {}",
                var_name, e
            ))
        })?;

        jwks.validate()?;
        Ok(jwks)
    }

    /// Get a key by its key ID (kid)
    pub fn get_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Internal JWKS loader with Arc-wrapped storage
///
/// This loader holds the internal JWKS in memory and provides
/// thread-safe access to keys.
#[derive(Clone, Debug)]
pub struct InternalJwksLoader {
    jwks: Arc<InternalJwks>,
}

impl InternalJwksLoader {
    /// Create a new loader from an InternalJwks
    pub fn new(jwks: InternalJwks) -> Self {
        Self {
            jwks: Arc::new(jwks),
        }
    }

    /// Create a new loader from configuration
    ///
    /// Loads JWKS from file path (if configured) or environment variable (if configured).
    /// Returns an error if neither is configured or if loading fails.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Neither `internal_jwks_path` nor `internal_jwks_env` is configured
    /// - JWKS file/environment variable cannot be read
    /// - JWKS structure is invalid
    pub fn from_config(
        jwks_path: Option<&std::path::Path>,
        jwks_env: Option<&str>,
    ) -> Result<Self, AuthError> {
        // Try file path first
        if let Some(path) = jwks_path {
            tracing::info!(path = ?path, "Loading internal JWKS from file");
            let jwks = InternalJwks::from_file(path)?;
            return Ok(Self::new(jwks));
        }

        // Try environment variable
        if let Some(env_var) = jwks_env {
            tracing::info!(
                var = env_var,
                "Loading internal JWKS from environment variable"
            );
            let jwks = InternalJwks::from_env(env_var)?;
            return Ok(Self::new(jwks));
        }

        Err(AuthError::JwksError(
            "Internal JWKS not configured: set either internal_jwks_path or internal_jwks_env"
                .to_string(),
        ))
    }

    /// Get a key by its key ID (kid)
    ///
    /// Returns a clone of the key to avoid lifetime issues with Arc
    pub fn get_key(&self, kid: &str) -> Option<Jwk> {
        self.jwks.get_key(kid).cloned()
    }

    /// Get the issuer
    pub fn issuer(&self) -> &str {
        &self.jwks.issuer
    }

    /// Get the audience
    pub fn audience(&self) -> &str {
        &self.jwks.audience
    }
}

/// Validate an internal service JWT
///
/// This function:
/// 1. Decodes the JWT header to get the key ID (kid) and algorithm
/// 2. Retrieves the corresponding public key from the loader
/// 3. Verifies the JWT signature
/// 4. Validates standard claims (exp, nbf, iat)
/// 5. Validates issuer matches internal issuer
/// 6. Validates audience matches internal audience
/// 7. Extracts scopes from the `scope` claim
/// 8. Returns an AuthContext with InternalServiceJwt method
///
/// # Errors
///
/// Returns error if:
/// - JWT header is malformed
/// - Key ID (kid) not found in JWKS
/// - Signature verification fails
/// - Claims validation fails (exp, nbf, iat, iss, aud)
pub async fn validate_internal_jwt(
    token: &str,
    loader: &InternalJwksLoader,
) -> Result<AuthContext, AuthError> {
    // Decode JWT header to get kid and algorithm
    let header = decode_header(token).map_err(|e| {
        AuthError::InvalidTokenFormat(format!("Failed to decode JWT header: {}", e))
    })?;

    let kid = header.kid.ok_or_else(|| {
        AuthError::InvalidTokenFormat("JWT header missing 'kid' field".to_string())
    })?;

    // Get the key from loader
    let jwk = loader
        .get_key(&kid)
        .ok_or_else(|| AuthError::JwksError(format!("Key '{}' not found in internal JWKS", kid)))?;

    // Convert JWK to DecodingKey
    let decoding_key = jwk.to_decoding_key()?;

    // Set up validation
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[loader.issuer()]);
    validation.set_audience(&[loader.audience()]);

    // Verify and decode JWT
    let token_data = decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
        tracing::warn!(error = %e, "Internal JWT validation failed");
        AuthError::from(e)
    })?;

    let claims = token_data.claims;

    // Extract scopes from space-separated string
    let scopes: Vec<String> = claims
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Use tenant_id from claims if present, otherwise default to "internal"
    let tenant_id = claims.tenant_id.unwrap_or_else(|| "internal".to_string());

    // Create AuthContext with proper fields
    Ok(AuthContext {
        tenant_id,
        client_id: claims.sub.clone(),
        key_id: kid,
        auth_method: AuthMethod::InternalServiceJwt,
        scopes,
        issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
            .unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1)),
        jti: claims.jti,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_jwk(kid: &str) -> Jwk {
        Jwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            kid: kid.to_string(),
            alg: Some("EdDSA".to_string()),
            x: Some("test_public_key".to_string()),
            n: None,
            e: None,
            use_: Some("sig".to_string()),
        }
    }

    #[test]
    fn test_internal_jwks_creation() {
        let keys = vec![create_test_jwk("key-1")];
        let jwks = InternalJwks::new(
            "https://internal.inferadb.com".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            keys,
        );

        assert!(jwks.is_ok());
        let jwks = jwks.unwrap();
        assert_eq!(jwks.issuer, "https://internal.inferadb.com");
        assert_eq!(jwks.audience, "https://api.inferadb.com/internal");
        assert_eq!(jwks.keys.len(), 1);
    }

    #[test]
    fn test_internal_jwks_empty_keys() {
        let result = InternalJwks::new(
            "https://internal.inferadb.com".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            vec![],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one key"));
    }

    #[test]
    fn test_internal_jwks_missing_kid() {
        let mut key = create_test_jwk("key-1");
        key.kid = "".to_string();

        let result = InternalJwks::new(
            "https://internal.inferadb.com".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            vec![key],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("kid"));
    }

    #[test]
    fn test_internal_jwks_missing_alg() {
        let mut key = create_test_jwk("key-1");
        key.alg = None;

        let result = InternalJwks::new(
            "https://internal.inferadb.com".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            vec![key],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alg"));
    }

    #[test]
    fn test_internal_jwks_empty_alg() {
        let mut key = create_test_jwk("key-1");
        key.alg = Some("".to_string());

        let result = InternalJwks::new(
            "https://internal.inferadb.com".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            vec![key],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alg"));
    }

    #[test]
    fn test_internal_jwks_empty_issuer() {
        let keys = vec![create_test_jwk("key-1")];
        let result = InternalJwks::new(
            "".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            keys,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("issuer"));
    }

    #[test]
    fn test_get_key_by_kid() {
        let keys = vec![create_test_jwk("key-1"), create_test_jwk("key-2")];
        let jwks = InternalJwks::new(
            "https://internal.inferadb.com".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            keys,
        )
        .unwrap();

        let key = jwks.get_key("key-1");
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid, "key-1");

        let key = jwks.get_key("key-2");
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid, "key-2");

        let key = jwks.get_key("unknown");
        assert!(key.is_none());
    }

    #[test]
    fn test_internal_jwks_loader() {
        let keys = vec![create_test_jwk("key-1")];
        let jwks = InternalJwks::new(
            "https://internal.inferadb.com".to_string(),
            "https://api.inferadb.com/internal".to_string(),
            keys,
        )
        .unwrap();

        let loader = InternalJwksLoader::new(jwks);

        assert_eq!(loader.issuer(), "https://internal.inferadb.com");
        assert_eq!(loader.audience(), "https://api.inferadb.com/internal");

        let key = loader.get_key("key-1");
        assert!(key.is_some());
        assert_eq!(key.as_ref().unwrap().kid, "key-1");
    }

    #[test]
    fn test_jwks_from_env_missing() {
        let result = InternalJwks::from_env("NONEXISTENT_VAR");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not set"));
    }

    #[test]
    fn test_jwks_from_env_invalid_json() {
        std::env::set_var("TEST_JWKS_INVALID", "not valid json");
        let result = InternalJwks::from_env("TEST_JWKS_INVALID");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));
        std::env::remove_var("TEST_JWKS_INVALID");
    }

    #[test]
    fn test_jwks_from_env_valid() {
        let jwks_json = r#"{
            "issuer": "https://internal.inferadb.com",
            "audience": "https://api.inferadb.com/internal",
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key",
                "alg": "EdDSA",
                "x": "test_public_key",
                "use": "sig"
            }]
        }"#;

        std::env::set_var("TEST_JWKS_VALID", jwks_json);
        let result = InternalJwks::from_env("TEST_JWKS_VALID");
        assert!(result.is_ok());

        let jwks = result.unwrap();
        assert_eq!(jwks.issuer, "https://internal.inferadb.com");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, "test-key");

        std::env::remove_var("TEST_JWKS_VALID");
    }

    #[test]
    fn test_loader_from_config_file() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let jwks_path = temp_dir.join("test_internal_jwks.json");

        // Write test JWKS to file
        let jwks_json = r#"{
            "issuer": "https://internal.inferadb.com",
            "audience": "https://api.inferadb.com/internal",
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "file-key",
                "alg": "EdDSA",
                "x": "test_public_key",
                "use": "sig"
            }]
        }"#;

        let mut file = std::fs::File::create(&jwks_path).unwrap();
        file.write_all(jwks_json.as_bytes()).unwrap();

        // Test loading from file
        let result = InternalJwksLoader::from_config(Some(&jwks_path), None);
        assert!(result.is_ok());

        let loader = result.unwrap();
        let key = loader.get_key("file-key");
        assert!(key.is_some());

        // Cleanup
        std::fs::remove_file(&jwks_path).ok();
    }

    #[test]
    fn test_loader_from_config_env() {
        let jwks_json = r#"{
            "issuer": "https://internal.inferadb.com",
            "audience": "https://api.inferadb.com/internal",
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "env-key",
                "alg": "EdDSA",
                "x": "test_public_key",
                "use": "sig"
            }]
        }"#;

        std::env::set_var("TEST_LOADER_ENV", jwks_json);

        // Test loading from env
        let result = InternalJwksLoader::from_config(None, Some("TEST_LOADER_ENV"));
        assert!(result.is_ok());

        let loader = result.unwrap();
        let key = loader.get_key("env-key");
        assert!(key.is_some());

        std::env::remove_var("TEST_LOADER_ENV");
    }

    #[test]
    fn test_loader_from_config_file_priority() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let jwks_path = temp_dir.join("test_internal_jwks_priority.json");

        // Write test JWKS to file
        let file_jwks_json = r#"{
            "issuer": "https://internal.inferadb.com",
            "audience": "https://api.inferadb.com/internal",
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "file-key",
                "alg": "EdDSA",
                "x": "test_public_key",
                "use": "sig"
            }]
        }"#;

        let mut file = std::fs::File::create(&jwks_path).unwrap();
        file.write_all(file_jwks_json.as_bytes()).unwrap();

        // Set env var with different key
        let env_jwks_json = r#"{
            "issuer": "https://internal.inferadb.com",
            "audience": "https://api.inferadb.com/internal",
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "env-key",
                "alg": "EdDSA",
                "x": "test_public_key",
                "use": "sig"
            }]
        }"#;
        std::env::set_var("TEST_LOADER_PRIORITY", env_jwks_json);

        // Test that file takes priority
        let result =
            InternalJwksLoader::from_config(Some(&jwks_path), Some("TEST_LOADER_PRIORITY"));
        assert!(result.is_ok());

        let loader = result.unwrap();
        assert!(loader.get_key("file-key").is_some());
        assert!(loader.get_key("env-key").is_none());

        // Cleanup
        std::fs::remove_file(&jwks_path).ok();
        std::env::remove_var("TEST_LOADER_PRIORITY");
    }

    #[test]
    fn test_loader_from_config_no_source() {
        let result = InternalJwksLoader::from_config(None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not configured"));
    }
}
