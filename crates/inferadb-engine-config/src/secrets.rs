//! Secrets management
//!
//! Provides a unified interface for loading secrets from multiple sources:
//! - Environment variables (`EnvSecretProvider`)
//! - Files (`FileSecretProvider`)
//! - AWS Secrets Manager (`AwsSecretsProvider`, requires `aws-secrets` feature)
//! - Google Cloud Secret Manager (`GcpSecretsProvider`, requires `gcp-secrets` feature)
//! - Azure Key Vault (`AzureSecretsProvider`, requires `azure-secrets` feature)
//! - In-memory storage (`MemorySecretProvider`)
//! - Composite provider (`CompositeSecretProvider`)
//!
//! ## Cloud Provider Setup
//!
//! ### Google Cloud Platform
//!
//! Enable the `gcp-secrets` feature and set up Application Default Credentials:
//!
//! ```bash
//! # For local development
//! gcloud auth application-default login
//!
//! # For production (set environment variable)
//! export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
//! ```
//!
//! ### Azure
//!
//! Enable the `azure-secrets` feature and authenticate:
//!
//! ```bash
//! # For local development
//! az login
//!
//! # For production, use managed identity or service principal
//! # (environment variables or Azure metadata service)
//! ```
//!
//! ### AWS
//!
//! Enable the `aws-secrets` feature and configure credentials:
//!
//! ```bash
//! # Configure AWS credentials
//! aws configure
//! ```
//!
//! ## Examples
//!
//! ### Using a single provider
//!
//! ```no_run
//! use inferadb_engine_config::secrets::{EnvSecretProvider, SecretProvider};
//!
//! let provider = EnvSecretProvider;
//! let api_key = provider.get("API_KEY")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Using composite provider for fallback
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use inferadb_engine_config::secrets::{CompositeSecretProvider, EnvSecretProvider, FileSecretProvider, SecretProvider};
//!
//! let provider = CompositeSecretProvider::new()
//!     .add_provider(Box::new(EnvSecretProvider))
//!     .add_provider(Box::new(FileSecretProvider::new("/etc/secrets")));
//!
//! // Tries environment variables first, then files
//! let secret = provider.get("DATABASE_PASSWORD")?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Using cloud providers
//!
//! ```no_run
//! # #[cfg(feature = "gcp-secrets")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use inferadb_engine_config::secrets::{GcpSecretsProvider, SecretProvider};
//!
//! let provider = GcpSecretsProvider::new("my-project-id").await?;
//! let api_key = provider.get("api-key")?;
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, fs, path::Path};

#[cfg(feature = "aws-secrets")]
use aws_config::BehaviorVersion;
#[cfg(feature = "aws-secrets")]
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
#[cfg(feature = "azure-secrets")]
use azure_identity::DeveloperToolsCredential;
#[cfg(feature = "azure-secrets")]
use azure_security_keyvault_secrets::SecretClient;
#[cfg(feature = "gcp-secrets")]
use google_cloud_secretmanager_v1::client::SecretManagerService;
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
/// Fetches secrets from Google Cloud Secret Manager using the official Google Cloud SDK.
///
/// # Authentication
///
/// This provider uses [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials).
/// Credentials are automatically discovered in the following order:
///
/// 1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable (path to service account JSON)
/// 2. `~/.config/gcloud/application_default_credentials.json` (created by `gcloud auth
///    application-default login`)
/// 3. GCP metadata server (when running on GCP infrastructure)
///
/// # Setup
///
/// For local development:
/// ```bash
/// gcloud auth application-default login
/// ```
///
/// For production:
/// ```bash
/// export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
/// ```
///
/// # Example
///
/// ```no_run
/// use inferadb_engine_config::secrets::{GcpSecretsProvider, SecretProvider};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let provider = GcpSecretsProvider::new("my-gcp-project-id").await?;
///     let db_password = provider.get_async("database-password").await?;
///     println!("Got password from GCP Secret Manager");
///     Ok(())
/// }
/// ```
#[cfg(feature = "gcp-secrets")]
pub struct GcpSecretsProvider {
    client: SecretManagerService,
    project_id: String,
}

#[cfg(feature = "gcp-secrets")]
impl GcpSecretsProvider {
    /// Create a new GCP Secret Manager provider
    ///
    /// # Arguments
    ///
    /// * `project_id` - The GCP project ID where secrets are stored
    ///
    /// # Errors
    ///
    /// Returns `SecretError::InvalidFormat` if:
    /// - Application Default Credentials cannot be found
    /// - The credentials are invalid or expired
    /// - Network connection to GCP fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use inferadb_engine_config::secrets::GcpSecretsProvider;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = GcpSecretsProvider::new("my-project-id").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(project_id: impl Into<String>) -> Result<Self, SecretError> {
        let project_id = project_id.into();

        let client = SecretManagerService::builder().build().await.map_err(|e| {
            SecretError::InvalidFormat(format!("Failed to create GCP Secret Manager client: {}", e))
        })?;

        Ok(Self { client, project_id })
    }

    /// Get a secret from GCP Secret Manager (async)
    ///
    /// Retrieves the latest version of the specified secret.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret name (not the full resource path)
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `SecretError::NotFound` if the secret doesn't exist
    /// - `SecretError::InvalidFormat` if:
    ///   - The secret payload is missing
    ///   - The secret data is not valid UTF-8
    ///   - Network or permission errors occur
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use inferadb_engine_config::secrets::GcpSecretsProvider;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = GcpSecretsProvider::new("my-project-id").await?;
    /// let secret = provider.get_async("api-key").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_async(&self, key: &str) -> Result<String, SecretError> {
        // Build the full resource name for the latest version
        let name = format!("projects/{}/secrets/{}/versions/latest", self.project_id, key);

        // Access the secret version
        let response =
            self.client.access_secret_version().set_name(name.clone()).send().await.map_err(
                |e| {
                    let error_msg = e.to_string();
                    if error_msg.contains("NOT_FOUND") || error_msg.contains("not found") {
                        SecretError::NotFound(key.to_string())
                    } else {
                        SecretError::InvalidFormat(format!(
                            "GCP Secret Manager error for '{}': {}",
                            key, error_msg
                        ))
                    }
                },
            )?;

        // Extract the payload data
        let payload = response.payload.ok_or_else(|| SecretError::NotFound(key.to_string()))?;

        // payload.data is Bytes, convert to Vec<u8>
        let data = payload.data.to_vec();

        // Convert bytes to UTF-8 string
        String::from_utf8(data).map_err(|e| {
            SecretError::InvalidFormat(format!("Secret '{}' contains invalid UTF-8: {}", key, e))
        })
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
/// Fetches secrets from Azure Key Vault using the official Azure SDK.
///
/// # Authentication
///
/// This provider uses `DeveloperToolsCredential` which tries the following methods in order:
///
/// 1. Azure CLI (`az login`)
/// 2. Azure Developer CLI (`azd auth login`)
///
/// For production environments, consider using:
/// - `ManagedIdentityCredential` for Azure-hosted applications
/// - `ClientSecretCredential` for service principals
///
/// # Setup
///
/// For local development:
/// ```bash
/// az login
/// ```
///
/// For production, ensure the application has appropriate Azure credentials configured
/// (managed identity, service principal environment variables, etc.).
///
/// # Example
///
/// ```no_run
/// use inferadb_engine_config::secrets::{AzureSecretsProvider, SecretProvider};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let provider = AzureSecretsProvider::new("https://my-keyvault.vault.azure.net/").await?;
///     let api_key = provider.get_async("api-key").await?;
///     println!("Got API key from Azure Key Vault");
///     Ok(())
/// }
/// ```
#[cfg(feature = "azure-secrets")]
pub struct AzureSecretsProvider {
    client: SecretClient,
    #[allow(dead_code)]
    vault_url: String,
}

#[cfg(feature = "azure-secrets")]
impl AzureSecretsProvider {
    /// Create a new Azure Key Vault provider
    ///
    /// # Arguments
    ///
    /// * `vault_url` - The Key Vault URL (e.g., "https://my-keyvault.vault.azure.net/")
    ///
    /// # Errors
    ///
    /// Returns `SecretError::InvalidFormat` if:
    /// - Azure credentials cannot be found (run `az login` or `azd auth login`)
    /// - The vault URL is invalid
    /// - Network connection to Azure fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use inferadb_engine_config::secrets::AzureSecretsProvider;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = AzureSecretsProvider::new("https://my-vault.vault.azure.net/").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(vault_url: impl Into<String>) -> Result<Self, SecretError> {
        let vault_url_str = vault_url.into();

        // Create credential using DeveloperToolsCredential (tries Azure CLI, then Azure Developer
        // CLI)
        let credential = DeveloperToolsCredential::new(None).map_err(|e| {
            SecretError::InvalidFormat(format!("Failed to create Azure credentials: {}", e))
        })?;

        // Create SecretClient
        let client = SecretClient::new(&vault_url_str, credential, None).map_err(|e| {
            SecretError::InvalidFormat(format!("Failed to create Azure Key Vault client: {}", e))
        })?;

        Ok(Self { client, vault_url: vault_url_str })
    }

    /// Get a secret from Azure Key Vault (async)
    ///
    /// Retrieves the latest version of the specified secret.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret name
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `SecretError::NotFound` if the secret doesn't exist or has no value
    /// - `SecretError::InvalidFormat` if network or permission errors occur
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use inferadb_engine_config::secrets::AzureSecretsProvider;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = AzureSecretsProvider::new("https://my-vault.vault.azure.net/").await?;
    /// let secret = provider.get_async("database-password").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_async(&self, key: &str) -> Result<String, SecretError> {
        // Get the secret (no version specified = latest)
        let response = self.client.get_secret(key, None).await.map_err(|e| {
            let error_msg = e.to_string();
            if error_msg.contains("NotFound") || error_msg.contains("not found") {
                SecretError::NotFound(key.to_string())
            } else {
                SecretError::InvalidFormat(format!(
                    "Azure Key Vault error for '{}': {}",
                    key, error_msg
                ))
            }
        })?;

        // Extract the secret from the response body
        let secret = response.into_body().map_err(|e| {
            SecretError::InvalidFormat(format!("Failed to parse Azure secret '{}': {}", key, e))
        })?;

        // Extract the value field
        secret.value.ok_or_else(|| {
            SecretError::NotFound(format!("Secret '{}' exists but has no value", key))
        })
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
        std::env::set_var("INFERADB_TEST_SECRET", "test_value");

        let provider = EnvSecretProvider;
        assert!(provider.has("INFERADB_TEST_SECRET"));
        assert_eq!(provider.get("INFERADB_TEST_SECRET").unwrap(), "test_value");
        assert!(!provider.has("NONEXISTENT_VAR"));

        // Clean up
        std::env::remove_var("INFERADB_TEST_SECRET");
    }

    #[test]
    fn test_file_provider_nonexistent_path() {
        let provider = FileSecretProvider::new("/nonexistent/path/to/secrets");
        assert!(!provider.has("some_secret"));
        assert!(provider.get("some_secret").is_err());
    }

    /// Integration test for GCP Secret Manager
    ///
    /// This test requires:
    /// 1. A GCP project with Secret Manager API enabled
    /// 2. A secret named "test-secret" with value "test-value"
    /// 3. Valid Application Default Credentials (run `gcloud auth application-default login`)
    /// 4. Environment variable GCP_PROJECT_ID set to your project ID
    ///
    /// Run with: cargo test --features gcp-secrets test_gcp_secrets_provider -- --ignored
    /// --nocapture
    #[cfg(feature = "gcp-secrets")]
    #[tokio::test]
    #[ignore] // Requires GCP credentials and project setup
    async fn test_gcp_secrets_provider() {
        let project_id =
            std::env::var("GCP_PROJECT_ID").expect("GCP_PROJECT_ID environment variable not set");

        // Create provider
        let provider = GcpSecretsProvider::new(&project_id)
            .await
            .expect("Failed to create GCP secrets provider");

        // Test accessing an existing secret
        // Note: You need to create a secret named "test-secret" with value "test-value" in your GCP
        // project
        match provider.get_async("test-secret").await {
            Ok(value) => {
                println!("Successfully retrieved secret: {}", value);
                assert!(!value.is_empty());
            },
            Err(SecretError::NotFound(_)) => {
                println!(
                    "Secret 'test-secret' not found. Create it in your GCP project for full test."
                );
            },
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Test error handling for non-existent secret
        let result = provider.get_async("non-existent-secret-12345").await;
        assert!(matches!(result, Err(SecretError::NotFound(_))));
    }

    /// Integration test for Azure Key Vault
    ///
    /// This test requires:
    /// 1. An Azure Key Vault created
    /// 2. A secret named "test-secret" with value "test-value" in the vault
    /// 3. Valid Azure credentials (run `az login`)
    /// 4. Environment variable AZURE_VAULT_URL set to your vault URL (e.g., "https://my-vault.vault.azure.net/")
    ///
    /// Run with: cargo test --features azure-secrets test_azure_secrets_provider -- --ignored
    /// --nocapture
    #[cfg(feature = "azure-secrets")]
    #[tokio::test]
    #[ignore] // Requires Azure credentials and Key Vault setup
    async fn test_azure_secrets_provider() {
        let vault_url =
            std::env::var("AZURE_VAULT_URL").expect("AZURE_VAULT_URL environment variable not set");

        // Create provider
        let provider = AzureSecretsProvider::new(&vault_url)
            .await
            .expect("Failed to create Azure secrets provider");

        // Test accessing an existing secret
        // Note: You need to create a secret named "test-secret" in your Azure Key Vault
        match provider.get_async("test-secret").await {
            Ok(value) => {
                println!("Successfully retrieved secret: {}", value);
                assert!(!value.is_empty());
            },
            Err(SecretError::NotFound(_)) => {
                println!(
                    "Secret 'test-secret' not found. Create it in your Azure Key Vault for full test."
                );
            },
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Test error handling for non-existent secret
        let result = provider.get_async("non-existent-secret-12345").await;
        assert!(matches!(result, Err(SecretError::NotFound(_))));
    }

    /// Test composite provider with cloud providers
    ///
    /// This test verifies that cloud providers can be composed with other providers
    #[test]
    fn test_composite_with_cloud_providers() {
        // Create a memory provider as fallback
        let memory = MemorySecretProvider::new()
            .with_secret("local-secret", "local-value")
            .with_secret("fallback-secret", "fallback-value");

        let composite = CompositeSecretProvider::new().add_provider(Box::new(memory));

        // Should retrieve from memory provider
        assert_eq!(composite.get("local-secret").unwrap(), "local-value");
        assert_eq!(composite.get("fallback-secret").unwrap(), "fallback-value");
        assert!(composite.has("local-secret"));
        assert!(!composite.has("nonexistent"));
    }
}
