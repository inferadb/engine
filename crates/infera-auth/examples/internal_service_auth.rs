//! # Internal Service Authentication Example
//!
//! This example demonstrates how to set up internal service-to-service authentication
//! using Ed25519-signed JWTs. This pattern is used for secure communication between
//! InferaDB services that don't have tenant-specific credentials.
//!
//! ## Prerequisites
//!
//! 1. Generate an Ed25519 keypair and create a JWKS file
//! 2. Configure the server with internal JWKS path or environment variable
//! 3. Configure clients to sign JWTs with the private key
//!
//! ## Running this example
//!
//! ```bash
//! # Set the internal JWKS as an environment variable
//! export INFERADB_INTERNAL_JWKS='{"issuer":"https://internal.inferadb.com","audience":"https://api.inferadb.com/internal","keys":[...]}'
//!
//! # Run the example
//! cargo run --example internal_service_auth
//! ```

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    kid: String,
    x: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InternalJwks {
    issuer: String,
    audience: String,
    keys: Vec<Jwk>,
}

/// Internal JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct InternalClaims {
    iss: String,  // Issuer
    sub: String,  // Subject (service name)
    aud: String,  // Audience
    exp: u64,     // Expiration time
    nbf: u64,     // Not before
    iat: u64,     // Issued at
    jti: String,  // JWT ID (for replay protection)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Internal Service Authentication Example ===\n");

    // Step 1: Generate an Ed25519 keypair
    println!("Step 1: Generating Ed25519 keypair...");
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    println!("✓ Keypair generated\n");

    // Step 2: Create JWKS with public key
    println!("Step 2: Creating JWKS with public key...");
    let public_key_bytes = verifying_key.to_bytes();
    let public_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_key_bytes);

    let jwks = InternalJwks {
        issuer: "https://internal.inferadb.com".to_string(),
        audience: "https://api.inferadb.com/internal".to_string(),
        keys: vec![Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            kid: "internal-key-1".to_string(),
            x: public_key_b64,
        }],
    };

    let jwks_json = serde_json::to_string_pretty(&jwks)?;
    println!("JWKS:\n{}\n", jwks_json);

    // Step 3: Create internal JWT claims
    println!("Step 3: Creating internal JWT claims...");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = InternalClaims {
        iss: "https://internal.inferadb.com".to_string(),
        sub: "background-worker".to_string(),
        aud: "https://api.inferadb.com/internal".to_string(),
        exp: now + 300, // 5 minutes
        nbf: now,
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    println!("Claims: {:?}\n", claims);

    // Step 4: Sign JWT with private key
    println!("Step 4: Signing JWT with private key...");
    let private_bytes = signing_key.to_bytes();

    // Create PKCS8 DER encoding for Ed25519
    // This format is required by jsonwebtoken crate
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER version 0
        0x30, 0x05, // SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes
    ];
    pkcs8_der.extend_from_slice(&private_bytes);

    let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("internal-key-1".to_string());

    let token = encode(&header, &claims, &encoding_key)?;
    println!("✓ JWT signed\n");
    println!("JWT Token (truncated): {}...\n", &token[..50]);

    // Step 5: Demonstrate loading JWKS and validating
    println!("Step 5: Validating JWT with JWKS...");
    println!("In production, the server would:");
    println!("  1. Load JWKS from file or environment variable");
    println!("     let loader = InternalJwksLoader::from_env(\"INFERADB_INTERNAL_JWKS\")?;");
    println!("  2. Validate incoming JWT in the gRPC interceptor");
    println!("     let auth_ctx = validate_internal_jwt(&token, &loader).await?;");
    println!("  3. Use AuthContext in request handlers");
    println!("     let auth = extract_auth(&request)?;\n");

    // Step 6: Show configuration example
    println!("Step 6: Server Configuration Example\n");
    println!("config.yaml:");
    println!("  auth:");
    println!("    enabled: true");
    println!("    # Option 1: Load from file");
    println!("    internal_jwks_path: /etc/inferadb/internal-jwks.json");
    println!("    # Option 2: Load from environment variable");
    println!("    internal_jwks_env: INFERADB_INTERNAL_JWKS");
    println!("    internal_issuer: https://internal.inferadb.com");
    println!("    internal_audience: https://api.inferadb.com/internal\n");

    // Step 7: Show gRPC client usage
    println!("Step 7: gRPC Client Usage Example\n");
    println!("```rust");
    println!("use tonic::metadata::MetadataValue;");
    println!("use tonic::Request;");
    println!();
    println!("// Create gRPC request");
    println!("let mut request = Request::new(CheckRequest {{ /* ... */ }});");
    println!();
    println!("// Add Bearer token to metadata");
    println!("let token_header = format!(\"Bearer {{}}\", internal_jwt);");
    println!("request.metadata_mut().insert(");
    println!("    \"authorization\",");
    println!("    MetadataValue::try_from(&token_header)?,");
    println!(");");
    println!();
    println!("// Make authenticated request");
    println!("let response = client.check(request).await?;");
    println!("```\n");

    println!("=== Example Complete ===");
    println!("\nKey Takeaways:");
    println!("✓ Internal JWTs use Ed25519 signatures for security and performance");
    println!("✓ JWKS contains only public keys for verification");
    println!("✓ Private keys should be securely stored and never logged");
    println!("✓ JWTs include expiration and replay protection via jti claims");
    println!("✓ gRPC interceptor automatically validates and injects AuthContext");

    Ok(())
}
