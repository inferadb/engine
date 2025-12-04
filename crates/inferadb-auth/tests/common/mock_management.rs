//! Integration test fixtures and helpers for cross-service testing
//!
//! This module provides mock servers and utilities for testing integration
//! between the InferaDB server and the Management API.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing::get};
use infera_auth::management_client::OrgStatus;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

/// Counter for generating unique Snowflake-like IDs
static ID_COUNTER: AtomicI64 = AtomicI64::new(11897886526013449);

/// Generate a unique Snowflake-like ID for testing
pub fn generate_snowflake_id() -> i64 {
    ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Mock Management API server state
#[derive(Clone)]
pub struct MockManagementState {
    pub organizations: Arc<Mutex<HashMap<i64, MockOrganization>>>,
    pub vaults: Arc<Mutex<HashMap<i64, MockVault>>>,
    pub certificates: Arc<Mutex<HashMap<CertificateKey, MockCertificate>>>,
}

impl MockManagementState {
    /// Create a new mock state
    pub fn new() -> Self {
        Self {
            organizations: Arc::new(Mutex::new(HashMap::new())),
            vaults: Arc::new(Mutex::new(HashMap::new())),
            certificates: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add a mock organization
    pub fn add_organization(&self, org: MockOrganization) {
        self.organizations.lock().unwrap().insert(org.id, org);
    }

    /// Add a mock vault
    pub fn add_vault(&self, vault: MockVault) {
        self.vaults.lock().unwrap().insert(vault.id, vault);
    }

    /// Add a mock certificate
    pub fn add_certificate(&self, cert: MockCertificate) {
        let key =
            CertificateKey { org_id: cert.org_id, client_id: cert.client_id, cert_id: cert.id };
        self.certificates.lock().unwrap().insert(key, cert);
    }

    /// Remove an organization (simulate deletion)
    pub fn remove_organization(&self, org_id: i64) {
        self.organizations.lock().unwrap().remove(&org_id);
    }

    /// Suspend an organization
    pub fn suspend_organization(&self, org_id: i64) {
        if let Some(org) = self.organizations.lock().unwrap().get_mut(&org_id) {
            org.status = OrgStatus::Suspended;
        }
    }

    /// Clear all data
    pub fn clear(&self) {
        self.organizations.lock().unwrap().clear();
        self.vaults.lock().unwrap().clear();
        self.certificates.lock().unwrap().clear();
    }
}

impl Default for MockManagementState {
    fn default() -> Self {
        Self::new()
    }
}

/// Key for looking up certificates
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CertificateKey {
    pub org_id: i64,
    pub client_id: i64,
    pub cert_id: i64,
}

/// Mock organization data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockOrganization {
    pub id: i64,
    pub name: String,
    #[serde(rename = "status")]
    pub status: OrgStatus,
}

/// Mock vault data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockVault {
    pub id: i64,
    pub name: String,
    pub organization_id: i64,
}

/// Mock certificate data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockCertificate {
    pub id: i64,
    #[serde(skip)]
    pub org_id: i64,
    pub client_id: i64,
    pub public_key: String,
    pub algorithm: String,
}

/// Handler for GET /v1/organizations/{org_id}
async fn get_organization(
    Path(org_id): Path<i64>,
    axum::extract::State(state): axum::extract::State<MockManagementState>,
) -> impl IntoResponse {
    let orgs = state.organizations.lock().unwrap();

    match orgs.get(&org_id) {
        Some(org) => (StatusCode::OK, Json(org.clone())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Handler for GET /v1/vaults/{vault_id}
async fn get_vault(
    Path(vault_id): Path<i64>,
    axum::extract::State(state): axum::extract::State<MockManagementState>,
) -> impl IntoResponse {
    let vaults = state.vaults.lock().unwrap();

    match vaults.get(&vault_id) {
        Some(vault) => (StatusCode::OK, Json(vault.clone())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// JWK format for JWKS response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwkResponse {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub alg: String,
}

/// JWKS response format
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkResponse>,
}

/// Handler for GET /v1/organizations/{org_id}/jwks.json
async fn get_org_jwks(
    Path(org_id): Path<i64>,
    axum::extract::State(state): axum::extract::State<MockManagementState>,
) -> impl IntoResponse {
    let certs = state.certificates.lock().unwrap();

    // Find all certificates for this org
    let keys: Vec<JwkResponse> = certs
        .iter()
        .filter(|(key, _)| key.org_id == org_id)
        .map(|(key, cert)| {
            // Convert base64 standard to base64url
            let public_key_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &cert.public_key,
            )
            .unwrap_or_default();

            let x = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &public_key_bytes,
            );

            JwkResponse {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                kid: format!("org-{}-client-{}-cert-{}", key.org_id, key.client_id, key.cert_id),
                x,
                key_use: "sig".to_string(),
                alg: "EdDSA".to_string(),
            }
        })
        .collect();

    (StatusCode::OK, Json(JwksResponse { keys }))
}

/// Start a mock Management API server
///
/// Returns the base URL and a handle to the server task
pub async fn start_mock_management_server(state: MockManagementState) -> (String, JoinHandle<()>) {
    let app = Router::new()
        // Internal endpoints used by ManagementClient
        .route("/internal/organizations/{org_id}", get(get_organization))
        .route("/internal/vaults/{vault_id}", get(get_vault))
        // Public JWKS endpoint (used by certificate cache)
        .route("/v1/organizations/{org_id}/jwks.json", get(get_org_jwks))
        .with_state(state);

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

/// Helper to create a test organization
pub fn create_test_organization(name: &str, status: OrgStatus) -> MockOrganization {
    MockOrganization { id: generate_snowflake_id(), name: name.to_string(), status }
}

/// Helper to create a test vault
pub fn create_test_vault(name: &str, org_id: i64) -> MockVault {
    MockVault { id: generate_snowflake_id(), name: name.to_string(), organization_id: org_id }
}

/// Helper to create a test certificate with Ed25519 key
pub fn create_test_certificate(
    org_id: i64,
    client_id: i64,
) -> (MockCertificate, ed25519_dalek::SigningKey) {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Encode public key as base64
    let public_key_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        verifying_key.as_bytes(),
    );

    let cert = MockCertificate {
        id: generate_snowflake_id(),
        org_id,
        client_id,
        public_key: public_key_base64,
        algorithm: "EdDSA".to_string(),
    };

    (cert, signing_key)
}

/// Generate a JWT signed with the given key
pub fn generate_jwt_with_key(
    signing_key: &ed25519_dalek::SigningKey,
    kid: &str,
    vault: i64,
    organization: i64,
    exp_secs: i64,
) -> String {
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: String,
        exp: u64,
        iat: u64,
        jti: String,
        vault: String,
        organization: String,
    }

    let now = Utc::now().timestamp();
    let claims = Claims {
        iss: "test-issuer".to_string(),
        sub: "test-subject".to_string(),
        aud: "https://api.inferadb.com".to_string(),
        exp: (now + exp_secs) as u64,
        iat: now as u64,
        jti: Uuid::new_v4().to_string(),
        vault: vault.to_string(),
        organization: organization.to_string(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());

    // Convert Ed25519 signing key to DER format for jsonwebtoken
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

    let encoding_key =
        EncodingKey::from_ed_pem(pem.as_bytes()).expect("Failed to create encoding key");

    encode(&header, &claims, &encoding_key).expect("Failed to encode JWT")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_organization_endpoint() {
        let state = MockManagementState::new();
        let org = create_test_organization("Test Org", OrgStatus::Active);
        let org_id = org.id;
        state.add_organization(org);

        let (base_url, _handle) = start_mock_management_server(state).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/internal/organizations/{}", base_url, org_id))
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::OK);
        let org_response: MockOrganization = response.json().await.unwrap();
        assert_eq!(org_response.id, org_id);
        assert_eq!(org_response.name, "Test Org");
    }

    #[tokio::test]
    async fn test_mock_server_vault_endpoint() {
        let state = MockManagementState::new();
        let org_id = generate_snowflake_id();
        let vault = create_test_vault("Test Vault", org_id);
        let vault_id = vault.id;
        state.add_vault(vault);

        let (base_url, _handle) = start_mock_management_server(state).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/internal/vaults/{}", base_url, vault_id))
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::OK);
        let vault_response: MockVault = response.json().await.unwrap();
        assert_eq!(vault_response.id, vault_id);
        assert_eq!(vault_response.organization_id, org_id);
    }

    #[tokio::test]
    async fn test_mock_server_jwks_endpoint() {
        let state = MockManagementState::new();
        let org_id = generate_snowflake_id();
        let client_id = generate_snowflake_id();
        let (cert, _key) = create_test_certificate(org_id, client_id);
        let cert_id = cert.id;
        state.add_certificate(cert);

        let (base_url, _handle) = start_mock_management_server(state).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/v1/organizations/{}/jwks.json", base_url, org_id))
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::OK);
        let jwks_response: JwksResponse = response.json().await.unwrap();
        assert_eq!(jwks_response.keys.len(), 1);

        let jwk = &jwks_response.keys[0];
        assert_eq!(jwk.kid, format!("org-{}-client-{}-cert-{}", org_id, client_id, cert_id));
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
    }

    #[tokio::test]
    async fn test_mock_server_not_found() {
        let state = MockManagementState::new();
        let (base_url, _handle) = start_mock_management_server(state).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/internal/organizations/{}", base_url, generate_snowflake_id()))
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_create_test_certificate_generates_valid_key() {
        let org_id = generate_snowflake_id();
        let client_id = generate_snowflake_id();
        let (cert, _key) = create_test_certificate(org_id, client_id);

        assert_eq!(cert.org_id, org_id);
        assert_eq!(cert.client_id, client_id);
        assert_eq!(cert.algorithm, "EdDSA");
        assert!(!cert.public_key.is_empty());
    }

    #[test]
    fn test_generate_jwt_with_key() {
        let org_id = generate_snowflake_id();
        let client_id = generate_snowflake_id();
        let (cert, signing_key) = create_test_certificate(org_id, client_id);

        let vault_id = generate_snowflake_id();
        let organization_id = generate_snowflake_id();
        let kid = format!("org-{}-client-{}-cert-{}", org_id, client_id, cert.id);

        let jwt = generate_jwt_with_key(&signing_key, &kid, vault_id, organization_id, 300);

        // JWT should have 3 parts
        assert_eq!(jwt.split('.').count(), 3);
    }
}
