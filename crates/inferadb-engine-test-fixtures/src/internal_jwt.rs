//! Test helpers for generating internal service JWTs
//!
//! This module provides utilities for creating Ed25519 keypairs and signing
//! internal JWTs for testing purposes.

use base64::Engine;
use ed25519_dalek::SigningKey;
use inferadb_engine_auth::{Jwk, internal::InternalJwks};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

/// Internal JWT claims for testing
///
/// # Example
///
/// ```no_run
/// use inferadb_engine_test_fixtures::InternalClaims;
///
/// let now = chrono::Utc::now().timestamp() as u64;
/// let claims = InternalClaims::builder()
///     .iss("https://internal.inferadb.com")
///     .sub("control-plane")
///     .aud("https://api.inferadb.com/internal")
///     .exp(now + 3600)
///     .iat(now)
///     .scope("inferadb.admin")
///     .build();
/// ```
#[derive(Debug, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
#[allow(clippy::should_implement_trait)]
pub struct InternalClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

impl InternalClaims {
    /// Create default internal claims for testing
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self::builder()
            .iss("https://internal.inferadb.com")
            .sub("control-plane")
            .aud("https://api.inferadb.com/internal")
            .exp(now + 3600) // 1 hour from now
            .iat(now)
            .scope("inferadb.admin")
            .jti(uuid::Uuid::new_v4().to_string())
            .vault_id("12345678901234")
            .org_id("98765432109876")
            .build()
    }

    /// Create expired internal claims for testing
    pub fn expired() -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self::builder()
            .iss("https://internal.inferadb.com")
            .sub("control-plane")
            .aud("https://api.inferadb.com/internal")
            .exp(now - 3600) // 1 hour ago
            .iat(now - 7200)
            .scope("inferadb.admin")
            .jti(uuid::Uuid::new_v4().to_string())
            .vault_id("12345678901234")
            .org_id("98765432109876")
            .build()
    }

    /// Create internal claims with custom scope
    pub fn with_scope(scope: impl Into<String>) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self::builder()
            .iss("https://internal.inferadb.com")
            .sub("control-plane")
            .aud("https://api.inferadb.com/internal")
            .exp(now + 3600)
            .iat(now)
            .scope(scope)
            .jti(uuid::Uuid::new_v4().to_string())
            .vault_id("12345678901234")
            .org_id("98765432109876")
            .build()
    }

    /// Create internal claims with wrong issuer
    pub fn with_wrong_issuer() -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self::builder()
            .iss("https://wrong-issuer.com")
            .sub("control-plane")
            .aud("https://api.inferadb.com/internal")
            .exp(now + 3600)
            .iat(now)
            .scope("inferadb.admin")
            .jti(uuid::Uuid::new_v4().to_string())
            .vault_id("12345678901234")
            .org_id("98765432109876")
            .build()
    }

    /// Create internal claims with wrong audience
    pub fn with_wrong_audience() -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self::builder()
            .iss("https://internal.inferadb.com")
            .sub("control-plane")
            .aud("https://wrong-audience.com")
            .exp(now + 3600)
            .iat(now)
            .scope("inferadb.admin")
            .jti(uuid::Uuid::new_v4().to_string())
            .vault_id("12345678901234")
            .org_id("98765432109876")
            .build()
    }
}

/// Test keypair holder with both the signing key and JWKs
pub struct InternalKeyPair {
    pub signing_key: SigningKey,
    pub private_jwk: Jwk,
    pub public_jwk: Jwk,
}

/// Generate an Ed25519 keypair for internal JWT testing
///
/// Returns InternalKeyPair containing:
/// - signing_key: The actual Ed25519 signing key
/// - private_jwk: JWK with kid for the private key
/// - public_jwk: JWK for verification (goes in JWKS)
pub fn generate_internal_keypair() -> InternalKeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Encode keys as base64url
    let public_bytes = verifying_key.to_bytes();

    let x_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_bytes);

    let kid = uuid::Uuid::new_v4().to_string();

    // Create private JWK (for signing - stores kid)
    let private_jwk = Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        kid: kid.clone(),
        alg: Some("EdDSA".to_string()),
        x: Some(x_base64.clone()),
        n: None,
        e: None,
        use_: Some("sig".to_string()),
    };

    // Create public JWK (for verification)
    let public_jwk = Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        kid,
        alg: Some("EdDSA".to_string()),
        x: Some(x_base64),
        n: None,
        e: None,
        use_: Some("sig".to_string()),
    };

    InternalKeyPair { signing_key, private_jwk, public_jwk }
}

/// Generate an internal JWT signed with the provided keypair
///
/// # Arguments
///
/// * `keypair` - The InternalKeyPair containing the signing key
/// * `claims` - The claims to include in the JWT
///
/// # Returns
///
/// A signed JWT string
pub fn generate_internal_jwt(keypair: &InternalKeyPair, claims: InternalClaims) -> String {
    let private_bytes = keypair.signing_key.to_bytes();

    // Create PKCS8 DER encoding for Ed25519
    // Ed25519 private keys in PKCS#8 format have this structure
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER version 0
        0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ];
    pkcs8_der.extend_from_slice(&private_bytes);

    let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);

    // Create JWT header with kid
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keypair.private_jwk.kid.clone());

    // Encode JWT
    encode(&header, &claims, &encoding_key).expect("Failed to encode JWT")
}

/// Create an InternalJwks structure for testing
///
/// # Arguments
///
/// * `public_keys` - Vector of public JWKs to include
///
/// # Returns
///
/// An InternalJwks ready for use in tests
pub fn create_internal_jwks(public_keys: Vec<Jwk>) -> InternalJwks {
    InternalJwks::new(
        "https://internal.inferadb.com".to_string(),
        "https://api.inferadb.com/internal".to_string(),
        public_keys,
    )
    .expect("Failed to create InternalJwks")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_internal_keypair();

        // Both JWKs should have same kid
        assert_eq!(keypair.private_jwk.kid, keypair.public_jwk.kid);

        // Both should be OKP/Ed25519
        assert_eq!(keypair.private_jwk.kty, "OKP");
        assert_eq!(keypair.private_jwk.crv, Some("Ed25519".to_string()));
        assert_eq!(keypair.public_jwk.kty, "OKP");
        assert_eq!(keypair.public_jwk.crv, Some("Ed25519".to_string()));

        // Both should have x parameter
        assert!(keypair.private_jwk.x.is_some());
        assert!(keypair.public_jwk.x.is_some());
    }

    #[test]
    fn test_default_claims() {
        let claims = InternalClaims::default();
        assert_eq!(claims.iss, "https://internal.inferadb.com");
        assert_eq!(claims.aud, "https://api.inferadb.com/internal");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_expired_claims() {
        let claims = InternalClaims::expired();
        let now = chrono::Utc::now().timestamp() as u64;
        assert!(claims.exp < now);
    }

    #[test]
    fn test_create_internal_jwks() {
        let keypair = generate_internal_keypair();
        let jwks = create_internal_jwks(vec![keypair.public_jwk]);

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.issuer, "https://internal.inferadb.com");
        assert_eq!(jwks.audience, "https://api.inferadb.com/internal");
    }

    #[test]
    fn test_generate_jwt() {
        let keypair = generate_internal_keypair();
        let claims = InternalClaims::default();
        let jwt = generate_internal_jwt(&keypair, claims);

        // JWT should have 3 parts
        assert_eq!(jwt.split('.').count(), 3);
    }

    // --- TDD tests for bon builder ---

    #[test]
    fn test_builder_with_all_required_fields() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = InternalClaims::builder()
            .iss("https://test.local")
            .sub("user:test")
            .aud("engine")
            .exp(now + 3600)
            .iat(now)
            .scope("read:relationships")
            .build();

        assert_eq!(claims.iss, "https://test.local");
        assert_eq!(claims.sub, "user:test");
        assert_eq!(claims.aud, "engine");
        assert_eq!(claims.exp, now + 3600);
        assert_eq!(claims.iat, now);
        assert_eq!(claims.scope, "read:relationships");
        // Optional fields default to None
        assert!(claims.jti.is_none());
        assert!(claims.vault_id.is_none());
        assert!(claims.org_id.is_none());
    }

    #[test]
    fn test_builder_with_optional_fields() {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = InternalClaims::builder()
            .iss("https://test.local")
            .sub("user:test")
            .aud("engine")
            .exp(now + 3600)
            .iat(now)
            .scope("read")
            .jti("unique-id")
            .vault_id("vault123")
            .org_id("org456")
            .build();

        assert_eq!(claims.jti, Some("unique-id".to_string()));
        assert_eq!(claims.vault_id, Some("vault123".to_string()));
        assert_eq!(claims.org_id, Some("org456".to_string()));
    }

    #[test]
    fn test_builder_replaces_expired_factory() {
        // Builder can create expired claims like the factory method
        let now = chrono::Utc::now().timestamp() as u64;
        let expired = InternalClaims::builder()
            .iss("https://internal.inferadb.com")
            .sub("control-plane")
            .aud("https://api.inferadb.com/internal")
            .exp(now - 3600) // 1 hour ago - expired
            .iat(now - 7200)
            .scope("inferadb.admin")
            .build();

        assert!(expired.exp < now);
    }

    #[test]
    fn test_builder_replaces_with_scope_factory() {
        // Builder can create scoped claims like the factory method
        let now = chrono::Utc::now().timestamp() as u64;
        let scoped = InternalClaims::builder()
            .iss("https://internal.inferadb.com")
            .sub("control-plane")
            .aud("https://api.inferadb.com/internal")
            .exp(now + 3600)
            .iat(now)
            .scope("custom:scope")
            .build();

        assert_eq!(scoped.scope, "custom:scope");
    }

    #[test]
    fn test_builder_replaces_with_wrong_issuer_factory() {
        // Builder can create wrong issuer claims like the factory method
        let now = chrono::Utc::now().timestamp() as u64;
        let wrong_issuer = InternalClaims::builder()
            .iss("https://wrong-issuer.com")
            .sub("control-plane")
            .aud("https://api.inferadb.com/internal")
            .exp(now + 3600)
            .iat(now)
            .scope("inferadb.admin")
            .build();

        assert_eq!(wrong_issuer.iss, "https://wrong-issuer.com");
    }

    #[test]
    fn test_builder_into_string_ergonomics() {
        // Test that string literals work without .to_string()
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = InternalClaims::builder()
            .iss("literal-iss")
            .sub("literal-sub")
            .aud("literal-aud")
            .exp(now + 3600)
            .iat(now)
            .scope("literal-scope")
            .build();

        assert_eq!(claims.iss, "literal-iss");
        assert_eq!(claims.sub, "literal-sub");
    }
}
