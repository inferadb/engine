//! Secrets management
//!
//! Handles loading secrets from environment variables, files, and cloud secret managers

use std::{collections::HashMap, fs, path::Path};

#[cfg(feature = "aws-secrets")]
use aws_config::BehaviorVersion;
#[cfg(feature = "aws-secrets")]
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
// Azure Key Vault support is temporarily disabled pending API updates
// #[cfg(feature = "azure-secrets")]
// use azure_security_keyvault::SecretClient;
// GCP Secret Manager support is temporarily disabled pending API updates
// #[cfg(feature = "gcp-secrets")]
// use google_secretmanager1::SecretManager;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Failed to read secret file: {0}")]
    FileReadError(#[from] std::io::Error),

    #[error("Invalid secret format: {0}")]
    InvalidFormat(String),
}

/// Secret provider interface
pub trait SecretProvider: Send + Sync {
    /// Get a secret by key
    fn get(&self, key: &str) -> Result<String, SecretError>;

    /// Check if a secret exists
    fn has(&self, key: &str) -> bool;
}

/// Environment variable secret provider
pub struct EnvSecretProvider;

impl SecretProvider for EnvSecretProvider {
    fn get(&self, key: &str) -> Result<String, SecretError> {
        std::env::var(key).map_err(|_| SecretError::NotFound(key.to_string()))
    }

    fn has(&self, key: &str) -> bool {
        std::env::var(key).is_ok()
    }
}

/// File-based secret provider
///
/// Reads secrets from individual files in a directory
/// (useful for Docker secrets or Kubernetes mounted secrets)
pub struct FileSecretProvider {
    base_path: String,
}

impl FileSecretProvider {
    pub fn new(base_path: impl Into<String>) -> Self {
        Self { base_path: base_path.into() }
    }
}

impl SecretProvider for FileSecretProvider {
    fn get(&self, key: &str) -> Result<String, SecretError> {
        let path = Path::new(&self.base_path).join(key);

        if !path.exists() {
            return Err(SecretError::NotFound(key.to_string()));
        }

        let content = fs::read_to_string(&path)?;

        // Trim whitespace and newlines
        Ok(content.trim().to_string())
    }

    fn has(&self, key: &str) -> bool {
        Path::new(&self.base_path).join(key).exists()
    }
}

/// Composite secret provider
///
/// Tries multiple providers in order
pub struct CompositeSecretProvider {
    providers: Vec<Box<dyn SecretProvider>>,
}

impl CompositeSecretProvider {
    pub fn new() -> Self {
        Self { providers: Vec::new() }
    }

    pub fn add_provider(mut self, provider: Box<dyn SecretProvider>) -> Self {
        self.providers.push(provider);
        self
    }
}

impl Default for CompositeSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for CompositeSecretProvider {
    fn get(&self, key: &str) -> Result<String, SecretError> {
        for provider in &self.providers {
            if let Ok(value) = provider.get(key) {
                return Ok(value);
            }
        }
        Err(SecretError::NotFound(key.to_string()))
    }

    fn has(&self, key: &str) -> bool {
        self.providers.iter().any(|p| p.has(key))
    }
}

/// In-memory secret provider (for testing)
pub struct MemorySecretProvider {
    secrets: HashMap<String, String>,
}

impl MemorySecretProvider {
    pub fn new() -> Self {
        Self { secrets: HashMap::new() }
    }

    pub fn with_secret(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets.insert(key.into(), value.into());
        self
    }
}

impl Default for MemorySecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for MemorySecretProvider {
    fn get(&self, key: &str) -> Result<String, SecretError> {
        self.secrets.get(key).cloned().ok_or_else(|| SecretError::NotFound(key.to_string()))
    }

    fn has(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }
}

/// AWS Secrets Manager provider
///
/// Fetches secrets from AWS Secrets Manager
#[cfg(feature = "aws-secrets")]
pub struct AwsSecretsProvider {
    client: SecretsManagerClient,
    _region: String,
}

#[cfg(feature = "aws-secrets")]
impl AwsSecretsProvider {
    /// Create a new AWS Secrets Manager provider
    pub async fn new(region: impl Into<String>) -> Result<Self, SecretError> {
        let region_str = region.into();
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region_str.clone()))
            .load()
            .await;

        let client = SecretsManagerClient::new(&config);

        Ok(Self { client, _region: region_str })
    }

    /// Get a secret from AWS Secrets Manager (async)
    pub async fn get_async(&self, key: &str) -> Result<String, SecretError> {
        let result =
            self.client.get_secret_value().secret_id(key).send().await.map_err(|e| {
                SecretError::InvalidFormat(format!("AWS Secrets Manager error: {}", e))
            })?;

        result
            .secret_string()
            .ok_or_else(|| SecretError::NotFound(key.to_string()))
            .map(|s| s.to_string())
    }
}

#[cfg(feature = "aws-secrets")]
impl SecretProvider for AwsSecretsProvider {
    fn get(&self, key: &str) -> Result<String, SecretError> {
        // Synchronous wrapper - requires tokio runtime
        tokio::runtime::Handle::current().block_on(async { self.get_async(key).await })
    }

    fn has(&self, key: &str) -> bool {
        self.get(key).is_ok()
    }
}

/// GCP Secret Manager provider
///
/// Fetches secrets from Google Cloud Secret Manager
///
/// TODO: Update to use google-secretmanager1 v6+ API (breaking changes in hyper/oauth2)
/// The google-secretmanager1 crate has updated its dependencies and API.
/// This code needs to be updated to match the new API surface.
#[cfg(feature = "gcp-secrets")]
pub struct GcpSecretsProvider {
    _project_id: String,
}

#[cfg(feature = "gcp-secrets")]
impl GcpSecretsProvider {
    /// Create a new GCP Secret Manager provider
    pub async fn new(_project_id: impl Into<String>) -> Result<Self, SecretError> {
        // TODO: Implement using updated google-secretmanager1 v6+ API
        // The API has changed significantly with hyper 1.0 and new oauth2 structure
        Err(SecretError::InvalidFormat(
            "GCP Secret Manager support requires API updates for google-secretmanager1 v6+".to_string()
        ))
    }

    /// Get a secret from GCP Secret Manager (async)
    pub async fn get_async(&self, _key: &str) -> Result<String, SecretError> {
        Err(SecretError::InvalidFormat(
            "GCP Secret Manager support requires API updates".to_string()
        ))
    }
}

#[cfg(feature = "gcp-secrets")]
impl SecretProvider for GcpSecretsProvider {
    fn get(&self, key: &str) -> Result<String, SecretError> {
        // Synchronous wrapper - requires tokio runtime
        tokio::runtime::Handle::current().block_on(async { self.get_async(key).await })
    }

    fn has(&self, key: &str) -> bool {
        self.get(key).is_ok()
    }
}

/// Azure Key Vault provider
///
/// Fetches secrets from Azure Key Vault
///
/// TODO: Update to use azure-identity v0.29+ and azure-security-keyvault v0.21+ APIs
/// The Azure SDK has updated with breaking changes to DefaultAzureCredential and SecretClient.
#[cfg(feature = "azure-secrets")]
pub struct AzureSecretsProvider {
    _vault_url: String,
}

#[cfg(feature = "azure-secrets")]
impl AzureSecretsProvider {
    /// Create a new Azure Key Vault provider
    pub async fn new(vault_url: impl Into<String>) -> Result<Self, SecretError> {
        // TODO: Implement using updated azure-identity v0.29+ API
        // DefaultAzureCredential and SecretClient APIs have changed
        let _vault_url_str = vault_url.into();
        Err(SecretError::InvalidFormat(
            "Azure Key Vault support requires API updates for azure-identity v0.29+".to_string()
        ))
    }

    /// Get a secret from Azure Key Vault (async)
    pub async fn get_async(&self, _key: &str) -> Result<String, SecretError> {
        Err(SecretError::InvalidFormat(
            "Azure Key Vault support requires API updates".to_string()
        ))
    }
}

#[cfg(feature = "azure-secrets")]
impl SecretProvider for AzureSecretsProvider {
    fn get(&self, key: &str) -> Result<String, SecretError> {
        // Synchronous wrapper - requires tokio runtime
        tokio::runtime::Handle::current().block_on(async { self.get_async(key).await })
    }

    fn has(&self, key: &str) -> bool {
        self.get(key).is_ok()
    }
}

/// Resolve secret references in strings
///
/// Replaces patterns like ${SECRET_NAME} with actual secret values
pub fn resolve_secrets(input: &str, provider: &dyn SecretProvider) -> Result<String, SecretError> {
    let mut result = input.to_string();
    let mut start = 0;

    while let Some(pos) = result[start..].find("${") {
        let abs_pos = start + pos;
        if let Some(end_pos) = result[abs_pos..].find('}') {
            let secret_key = &result[abs_pos + 2..abs_pos + end_pos];
            let secret_value = provider.get(secret_key)?;

            result.replace_range(abs_pos..abs_pos + end_pos + 1, &secret_value);
            start = abs_pos + secret_value.len();
        } else {
            break;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_provider() {
        let provider = MemorySecretProvider::new()
            .with_secret("API_KEY", "secret123")
            .with_secret("DB_PASSWORD", "pass456");

        assert!(provider.has("API_KEY"));
        assert_eq!(provider.get("API_KEY").unwrap(), "secret123");
        assert_eq!(provider.get("DB_PASSWORD").unwrap(), "pass456");
        assert!(!provider.has("NONEXISTENT"));
        assert!(provider.get("NONEXISTENT").is_err());
    }

    #[test]
    fn test_composite_provider() {
        let provider1 = MemorySecretProvider::new().with_secret("KEY1", "value1");

        let provider2 = MemorySecretProvider::new().with_secret("KEY2", "value2");

        let composite = CompositeSecretProvider::new()
            .add_provider(Box::new(provider1))
            .add_provider(Box::new(provider2));

        assert_eq!(composite.get("KEY1").unwrap(), "value1");
        assert_eq!(composite.get("KEY2").unwrap(), "value2");
        assert!(composite.has("KEY1"));
        assert!(composite.has("KEY2"));
        assert!(!composite.has("KEY3"));
    }

    #[test]
    fn test_composite_provider_priority() {
        let provider1 = MemorySecretProvider::new().with_secret("KEY", "value1");

        let provider2 = MemorySecretProvider::new().with_secret("KEY", "value2");

        let composite = CompositeSecretProvider::new()
            .add_provider(Box::new(provider1))
            .add_provider(Box::new(provider2));

        // Should return value from first provider
        assert_eq!(composite.get("KEY").unwrap(), "value1");
    }

    #[test]
    fn test_resolve_secrets_single() {
        let provider = MemorySecretProvider::new().with_secret("API_KEY", "secret123");

        let input = "connection_string: postgres://user:${API_KEY}@localhost/db";
        let result = resolve_secrets(input, &provider).unwrap();
        assert_eq!(result, "connection_string: postgres://user:secret123@localhost/db");
    }

    #[test]
    fn test_resolve_secrets_multiple() {
        let provider = MemorySecretProvider::new()
            .with_secret("USER", "admin")
            .with_secret("PASS", "secret123");

        let input = "connection_string: postgres://${USER}:${PASS}@localhost/db";
        let result = resolve_secrets(input, &provider).unwrap();
        assert_eq!(result, "connection_string: postgres://admin:secret123@localhost/db");
    }

    #[test]
    fn test_resolve_secrets_no_secrets() {
        let provider = MemorySecretProvider::new();

        let input = "plain text without secrets";
        let result = resolve_secrets(input, &provider).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_resolve_secrets_missing() {
        let provider = MemorySecretProvider::new();

        let input = "connection_string: postgres://user:${MISSING}@localhost/db";
        let result = resolve_secrets(input, &provider);
        assert!(result.is_err());
    }

    #[test]
    fn test_env_provider() {
        // Set test environment variable
        std::env::set_var("INFERA_TEST_SECRET", "test_value");

        let provider = EnvSecretProvider;
        assert!(provider.has("INFERA_TEST_SECRET"));
        assert_eq!(provider.get("INFERA_TEST_SECRET").unwrap(), "test_value");
        assert!(!provider.has("NONEXISTENT_VAR"));

        // Clean up
        std::env::remove_var("INFERA_TEST_SECRET");
    }

    #[test]
    fn test_file_provider_nonexistent_path() {
        let provider = FileSecretProvider::new("/nonexistent/path/to/secrets");
        assert!(!provider.has("some_secret"));
        assert!(provider.get("some_secret").is_err());
    }
}
