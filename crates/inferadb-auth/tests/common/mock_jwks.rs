use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{Json, Router, extract::Path, routing::get};
use ed25519_dalek::{SigningKey, VerifyingKey};
use infera_auth::{jwks_cache::Jwk, jwt::JwtClaims};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand_core::OsRng;
use serde_json::json;
use tokio::task::JoinHandle;

/// Thread-safe storage for test keypairs
static TEST_KEYPAIRS: OnceLock<Arc<Mutex<HashMap<String, SigningKey>>>> = OnceLock::new();

/// Get or create a keypair for a tenant
fn get_test_keypair_for_tenant(tenant: &str) -> SigningKey {
    let keypairs = TEST_KEYPAIRS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())));

    let mut map = keypairs.lock().unwrap();
    if let Some(key) = map.get(tenant) {
        key.clone()
    } else {
        let signing_key = SigningKey::generate(&mut OsRng);
        map.insert(tenant.to_string(), signing_key.clone());
        signing_key
    }
}

/// Convert Ed25519 public key to JWK format
fn public_key_to_jwk(tenant: &str, public_key: &VerifyingKey) -> Jwk {
    let kid = format!("{}-key-001", tenant);
    let x = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        public_key.as_bytes(),
    );

    Jwk {
        kty: "OKP".to_string(),
        use_: Some("sig".to_string()),
        kid,
        alg: Some("EdDSA".to_string()),
        crv: Some("Ed25519".to_string()),
        x: Some(x),
        n: None,
        e: None,
    }
}

/// Mock JWKS endpoint handler
async fn jwks_handler(Path(tenant_json): Path<String>) -> Json<serde_json::Value> {
    // Extract tenant from "{tenant}.json"
    let tenant = tenant_json.strip_suffix(".json").unwrap_or(&tenant_json);

    // Get or generate keypair for this tenant
    let signing_key = get_test_keypair_for_tenant(tenant);
    let verifying_key = signing_key.verifying_key();

    // Convert to JWK
    let jwk = public_key_to_jwk(tenant, &verifying_key);

    Json(json!({
        "keys": [jwk]
    }))
}

/// Start a mock JWKS server on a random port
pub async fn start_mock_jwks_server() -> (String, JoinHandle<()>) {
    let app = Router::new().route("/v1/organizations/{tenant}/jwks.json", get(jwks_handler));

    // Bind to random port
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", local_addr);

    // Spawn server
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, handle)
}

/// Generate a valid JWT signed by the tenant's private key
pub fn generate_jwt_for_mock_jwks(tenant: &str, scopes: Vec<String>, exp_secs: i64) -> String {
    let signing_key = get_test_keypair_for_tenant(tenant);
    let kid = format!("{}-key-001", tenant);

    let now = chrono::Utc::now().timestamp();

    let claims = JwtClaims {
        iss: format!("tenant:{}", tenant),
        sub: format!("tenant:{}", tenant),
        aud: "https://api.inferadb.com/evaluate".to_string(),
        exp: (now + exp_secs) as u64,
        iat: now as u64,
        nbf: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        scope: if scopes.is_empty() { String::new() } else { scopes.join(" ") },
        // For JWKS tests, use tenant name as org_id (simpler than Snowflake IDs)
        vault_id: None,
        org_id: Some(tenant.to_string()),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid);

    // Convert Ed25519 signing key to PEM format for jsonwebtoken
    let key_bytes = signing_key.to_bytes();

    // Create DER-encoded Ed25519 private key (PKCS#8)
    let mut der = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes
    ];
    der.extend_from_slice(&key_bytes);

    // Convert to PEM
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der)
    );

    let encoding_key =
        EncodingKey::from_ed_pem(pem.as_bytes()).expect("Failed to create encoding key");

    encode(&header, &claims, &encoding_key).expect("Failed to encode JWT")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_returns_jwks() {
        let (base_url, _handle) = start_mock_jwks_server().await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/v1/organizations/test-tenant/jwks.json", base_url))
            .send()
            .await
            .expect("Failed to send request");

        assert!(response.status().is_success());

        let jwks: serde_json::Value = response.json().await.expect("Failed to parse JSON");
        assert!(jwks.get("keys").is_some());
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_generate_jwt_for_tenant() {
        let jwt = generate_jwt_for_mock_jwks("acme", vec!["inferadb.evaluate".to_string()], 300);

        // JWT should have 3 parts
        assert_eq!(jwt.split('.').count(), 3);

        // Should be able to decode header
        let parts: Vec<&str> = jwt.split('.').collect();
        let header_json =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
                .expect("Failed to decode header");
        let header: serde_json::Value =
            serde_json::from_slice(&header_json).expect("Failed to parse header");

        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], "acme-key-001");
    }

    #[tokio::test]
    async fn test_keypair_consistency() {
        // Getting the same tenant's keypair twice should return the same key
        let key1 = get_test_keypair_for_tenant("consistent-tenant");
        let key2 = get_test_keypair_for_tenant("consistent-tenant");

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }
}
