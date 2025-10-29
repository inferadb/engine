//! Mock OAuth/OIDC server for integration testing
//!
//! This module provides a lightweight mock OAuth 2.0 / OIDC server that supports:
//! - OIDC discovery (/.well-known/openid-configuration)
//! - OAuth JWKS endpoint (/jwks.json)
//! - Token introspection endpoint (/introspect)
//! - JWT and opaque token generation

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::task::JoinHandle;

use infera_auth::jwt::JwtClaims;
use infera_auth::jwks_cache::Jwk;
use infera_auth::oauth::IntrospectionResponse;

/// Thread-safe storage for the OAuth server's signing key
static OAUTH_KEYPAIR: OnceLock<SigningKey> = OnceLock::new();

/// Registered opaque tokens with their introspection metadata
#[derive(Clone)]
pub struct OAuthServerState {
    opaque_tokens: Arc<Mutex<HashMap<String, IntrospectionResponse>>>,
}

impl OAuthServerState {
    fn new() -> Self {
        Self {
            opaque_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Get or create the OAuth server's signing key
fn get_oauth_signing_key() -> &'static SigningKey {
    OAUTH_KEYPAIR.get_or_init(|| SigningKey::generate(&mut rand::thread_rng()))
}

/// Convert Ed25519 public key to JWK format
fn oauth_public_key_to_jwk(public_key: &VerifyingKey) -> Jwk {
    let kid = "oauth-test-key-001".to_string();
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

/// OIDC Discovery configuration
#[derive(Debug, Serialize, Deserialize)]
struct OidcDiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    introspection_endpoint: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
}

/// OIDC discovery endpoint handler
async fn oidc_discovery_handler(
    State(base_url): State<String>,
) -> Json<OidcDiscoveryResponse> {
    Json(OidcDiscoveryResponse {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{}/authorize", base_url),
        token_endpoint: format!("{}/token", base_url),
        userinfo_endpoint: format!("{}/userinfo", base_url),
        jwks_uri: format!("{}/jwks.json", base_url),
        introspection_endpoint: format!("{}/introspect", base_url),
        response_types_supported: vec!["code".to_string(), "token".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
    })
}

/// OAuth JWKS endpoint handler
async fn oauth_jwks_handler() -> Json<serde_json::Value> {
    let signing_key = get_oauth_signing_key();
    let verifying_key = signing_key.verifying_key();
    let jwk = oauth_public_key_to_jwk(&verifying_key);

    Json(json!({
        "keys": [jwk]
    }))
}

/// Token introspection request
#[derive(Debug, Deserialize)]
struct IntrospectionRequest {
    token: String,
}

/// Token introspection endpoint handler
async fn introspection_handler(
    State(state): State<OAuthServerState>,
    axum::Form(req): axum::Form<IntrospectionRequest>,
) -> (StatusCode, Json<IntrospectionResponse>) {
    let tokens = state.opaque_tokens.lock().unwrap();

    if let Some(response) = tokens.get(&req.token) {
        (StatusCode::OK, Json(response.clone()))
    } else {
        // Token not found - return inactive
        (
            StatusCode::OK,
            Json(IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                sub: None,
                tenant_id: None,
            }),
        )
    }
}

/// Start a mock OAuth/OIDC server on a random port
///
/// Returns the base URL and server handle
pub async fn start_mock_oauth_server() -> (String, JoinHandle<()>, OAuthServerState) {
    let state = OAuthServerState::new();

    // Bind to random port first
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", local_addr);

    // Create app with combined state (base_url, oauth_state)
    let base_url_clone = base_url.clone();
    let state_clone = state.clone();

    let app = Router::new()
        .route("/.well-known/openid-configuration",
            get({
                let base_url = base_url_clone.clone();
                move |_: ()| {
                    let base_url = base_url.clone();
                    async move {
                        Json(OidcDiscoveryResponse {
                            issuer: base_url.clone(),
                            authorization_endpoint: format!("{}/authorize", base_url),
                            token_endpoint: format!("{}/token", base_url),
                            userinfo_endpoint: format!("{}/userinfo", base_url),
                            jwks_uri: format!("{}/jwks.json", base_url),
                            introspection_endpoint: format!("{}/introspect", base_url),
                            response_types_supported: vec!["code".to_string(), "token".to_string()],
                            subject_types_supported: vec!["public".to_string()],
                            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
                        })
                    }
                }
            })
        )
        .route("/jwks.json", get(oauth_jwks_handler))
        .route("/introspect",
            post({
                let state = state_clone.clone();
                move |axum::Form(req): axum::Form<IntrospectionRequest>| {
                    let state = state.clone();
                    async move {
                        let tokens = state.opaque_tokens.lock().unwrap();

                        if let Some(response) = tokens.get(&req.token) {
                            (StatusCode::OK, Json(response.clone()))
                        } else {
                            (
                                StatusCode::OK,
                                Json(IntrospectionResponse {
                                    active: false,
                                    scope: None,
                                    client_id: None,
                                    username: None,
                                    token_type: None,
                                    exp: None,
                                    iat: None,
                                    sub: None,
                                    tenant_id: None,
                                }),
                            )
                        }
                    }
                }
            })
        );

    // Spawn server
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, handle, state)
}

/// Generate a valid OAuth JWT signed by the OAuth provider's private key
///
/// # Arguments
///
/// * `issuer` - The OAuth issuer URL (typically the base URL of the mock server)
/// * `tenant_id` - The tenant identifier to include in the token
/// * `scopes` - The scopes to include in the token
/// * `exp_secs` - Expiration time in seconds from now (can be negative for expired tokens)
pub fn generate_oauth_jwt(
    issuer: &str,
    tenant_id: &str,
    scopes: Vec<&str>,
    exp_secs: i64,
) -> String {
    let signing_key = get_oauth_signing_key();
    let kid = "oauth-test-key-001".to_string();

    let now = chrono::Utc::now().timestamp();

    let claims = JwtClaims {
        iss: issuer.to_string(),
        sub: format!("user-{}", tenant_id),
        aud: "https://api.inferadb.com/evaluate".to_string(),
        exp: (now + exp_secs) as u64,
        iat: now as u64,
        nbf: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        scope: scopes.join(" "),
        tenant_id: Some(tenant_id.to_string()),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid);

    // Convert Ed25519 signing key to PEM format
    let key_bytes = signing_key.to_bytes();
    let mut der = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes
    ];
    der.extend_from_slice(&key_bytes);

    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der)
    );

    let encoding_key = EncodingKey::from_ed_pem(pem.as_bytes()).expect("Failed to create encoding key");
    encode(&header, &claims, &encoding_key).expect("Failed to encode JWT")
}

/// Generate an opaque token (random string)
pub fn generate_opaque_token() -> String {
    uuid::Uuid::new_v4().to_string().replace("-", "")
}

/// Register an opaque token with introspection metadata
pub fn register_opaque_token(
    state: &OAuthServerState,
    token: &str,
    metadata: IntrospectionResponse,
) {
    let mut tokens = state.opaque_tokens.lock().unwrap();
    tokens.insert(token.to_string(), metadata);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_oauth_server_oidc_discovery() {
        let (base_url, _handle, _state) = start_mock_oauth_server().await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/.well-known/openid-configuration", base_url))
            .send()
            .await
            .expect("Failed to send request");

        assert!(response.status().is_success());

        let discovery: OidcDiscoveryResponse = response.json().await.expect("Failed to parse JSON");
        assert_eq!(discovery.issuer, base_url);
        assert!(discovery.jwks_uri.contains("/jwks.json"));
        assert!(discovery.introspection_endpoint.contains("/introspect"));
    }

    #[tokio::test]
    async fn test_mock_oauth_server_jwks() {
        let (base_url, _handle, _state) = start_mock_oauth_server().await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/jwks.json", base_url))
            .send()
            .await
            .expect("Failed to send request");

        assert!(response.status().is_success());

        let jwks: serde_json::Value = response.json().await.expect("Failed to parse JSON");
        assert!(jwks.get("keys").is_some());
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        assert_eq!(jwks["keys"][0]["kid"], "oauth-test-key-001");
    }

    #[tokio::test]
    async fn test_generate_oauth_jwt() {
        let issuer = "https://oauth.example.com";
        let jwt = generate_oauth_jwt(issuer, "acme", vec!["read", "write"], 300);

        // JWT should have 3 parts
        assert_eq!(jwt.split('.').count(), 3);

        // Should be able to decode header
        let parts: Vec<&str> = jwt.split('.').collect();
        let header_json = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[0],
        )
        .expect("Failed to decode header");
        let header: serde_json::Value =
            serde_json::from_slice(&header_json).expect("Failed to parse header");

        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], "oauth-test-key-001");
    }

    #[tokio::test]
    async fn test_introspection_unregistered_token() {
        let (base_url, _handle, _state) = start_mock_oauth_server().await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/introspect", base_url))
            .form(&[("token", "unregistered-token")])
            .send()
            .await
            .expect("Failed to send request");

        assert!(response.status().is_success());

        let introspection: IntrospectionResponse = response.json().await.expect("Failed to parse JSON");
        assert!(!introspection.active);
    }

    #[tokio::test]
    async fn test_introspection_registered_token() {
        let (base_url, _handle, state) = start_mock_oauth_server().await;

        let token = generate_opaque_token();
        let metadata = IntrospectionResponse {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("test-client".to_string()),
            username: Some("testuser".to_string()),
            token_type: Some("Bearer".to_string()),
            exp: Some(9999999999),
            iat: Some(1234567890),
            sub: Some("user-123".to_string()),
            tenant_id: Some("acme".to_string()),
        };

        register_opaque_token(&state, &token, metadata.clone());

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/introspect", base_url))
            .form(&[("token", token.as_str())])
            .send()
            .await
            .expect("Failed to send request");

        assert!(response.status().is_success());

        let introspection: IntrospectionResponse = response.json().await.expect("Failed to parse JSON");
        assert!(introspection.active);
        assert_eq!(introspection.tenant_id, Some("acme".to_string()));
        assert_eq!(introspection.scope, Some("read write".to_string()));
    }
}
