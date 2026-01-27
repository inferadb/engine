//! Secrets management
//!
//! Provides a unified interface for loading secrets from multiple sources:
//! - Environment variables (`EnvSecretProvider`)
//! - Files (`FileSecretProvider`)
//! - In-memory storage (`MemorySecretProvider`)
//! - Composite provider (`CompositeSecretProvider`)
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

use std::{collections::HashMap, fs, path::Path};

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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
        let provider = EnvSecretProvider;

        // Test against a commonly-available env var (PATH exists on all Unix/Windows systems)
        // This avoids needing unsafe set_var/remove_var in Rust 2024 edition
        assert!(provider.has("PATH"));
        let path_value = provider.get("PATH");
        assert!(path_value.is_ok());
        assert!(!path_value.expect("PATH should exist").is_empty());

        // Test non-existent variable
        assert!(!provider.has("INFERADB_DEFINITELY_NONEXISTENT_VAR_12345"));
        assert!(provider.get("INFERADB_DEFINITELY_NONEXISTENT_VAR_12345").is_err());
    }

    #[test]
    fn test_file_provider_nonexistent_path() {
        let provider = FileSecretProvider::new("/nonexistent/path/to/secrets");
        assert!(!provider.has("some_secret"));
        assert!(provider.get("some_secret").is_err());
    }
}
