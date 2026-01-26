//! # Infera Config - Configuration Management
//!
//! Handles configuration loading from files, environment variables, and CLI args.
//!
//! ## Unified Configuration Format
//!
//! This crate supports a unified configuration format that allows both engine and control
//! services to share the same configuration file:
//!
//! ```yaml
//! engine:
//!   threads: 4
//!   logging: "info"
//!   listen:
//!     http: "127.0.0.1:8080"
//!   # ... other engine config
//!
//! control:
//!   threads: 4
//!   logging: "info"
//!   listen:
//!     http: "127.0.0.1:9090"
//!   # ... other control config (ignored by engine)
//! ```
//!
//! The engine will read its configuration from the `engine:` section. Any `control:` section
//! is ignored by the engine (and vice versa when control reads the same file).

#![deny(unsafe_code)]

pub mod hot_reload;
pub mod refresh;
pub mod secrets;
pub mod validation;

use std::path::Path;

use config::{Config as ConfigLoader, ConfigError, Environment, File};
pub use refresh::ConfigRefresher;
use serde::{Deserialize, Serialize};

/// Root configuration wrapper for unified config file support.
///
/// This allows both engine and control to read from the same YAML file,
/// with each service reading its own section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RootConfig {
    /// Engine-specific configuration
    #[serde(default)]
    pub engine: Config,
    // Note: `control` section may exist in the file but is ignored by engine
}

#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct Config {
    /// Number of worker threads for the async runtime
    #[serde(default = "default_threads")]
    #[builder(default = default_threads())]
    pub threads: usize,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_logging")]
    #[builder(default = default_logging())]
    pub logging: String,

    /// Server identity Ed25519 private key (PEM format) for signing server-to-control requests.
    /// This key is used to authenticate the server when making calls to the control API.
    /// If not provided, will be generated on startup and logged (not recommended for production).
    pub pem: Option<String>,

    #[serde(default)]
    #[builder(default)]
    pub listen: ListenConfig,
    #[serde(default = "default_storage")]
    #[builder(default = default_storage())]
    pub storage: String,
    #[serde(default)]
    #[builder(default)]
    pub ledger: LedgerConfig,
    #[serde(default)]
    #[builder(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    #[builder(default)]
    pub token: TokenConfig,
    #[serde(default)]
    #[builder(default)]
    pub replication: ReplicationConfig,
    /// Path to the IPL schema file defining types and relations.
    /// If not provided, an empty schema is used (all permission checks rely on direct
    /// relationships).
    pub schema: Option<String>,
}

/// Listen address configuration for API servers
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct ListenConfig {
    /// Client-facing HTTP/REST API server address
    /// Format: "host:port" (e.g., "0.0.0.0:8080")
    #[serde(default = "default_http")]
    #[builder(default = default_http())]
    pub http: String,

    /// Client-facing gRPC API server address
    /// Format: "host:port" (e.g., "0.0.0.0:8081")
    #[serde(default = "default_grpc")]
    #[builder(default = default_grpc())]
    pub grpc: String,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self { http: default_http(), grpc: default_grpc() }
    }
}

fn default_http() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_grpc() -> String {
    "0.0.0.0:8081".to_string()
}

fn default_threads() -> usize {
    num_cpus::get()
}

fn default_logging() -> String {
    "info".to_string()
}

fn default_storage() -> String {
    "ledger".to_string()
}

/// Ledger storage configuration (only used when storage = "ledger")
///
/// The Ledger backend provides cryptographically verifiable storage using
/// InferaDB Ledger. This is the target production storage backend.
#[derive(Debug, Clone, Serialize, Deserialize, Default, bon::Builder)]
pub struct LedgerConfig {
    /// Ledger server endpoint URL
    /// e.g., "http://localhost:50051" or "https://ledger.inferadb.com:50051"
    pub endpoint: Option<String>,

    /// Client ID for idempotency tracking
    /// Should be unique per engine instance to ensure correct duplicate detection
    /// e.g., "engine-prod-us-west-1a-001"
    pub client_id: Option<String>,

    /// Namespace ID for data scoping
    /// All keys will be stored within this namespace
    pub namespace_id: Option<i64>,

    /// Optional vault ID for finer-grained key scoping
    /// If set, keys are scoped to this specific vault within the namespace
    pub vault_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    #[builder(default = default_cache_enabled())]
    pub enabled: bool,

    #[serde(default = "default_cache_capacity")]
    #[builder(default = default_cache_capacity())]
    pub capacity: u64,

    #[serde(default = "default_cache_ttl")]
    #[builder(default = default_cache_ttl())]
    pub ttl: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            capacity: default_cache_capacity(),
            ttl: default_cache_ttl(),
        }
    }
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_capacity() -> u64 {
    10_000
}

fn default_cache_ttl() -> u64 {
    300
}

/// Token validation configuration
///
/// Controls how JWT tokens are validated, including JWKS caching,
/// timestamp tolerance, and token age limits.
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
pub struct TokenConfig {
    /// JWKS cache TTL in seconds
    #[serde(default = "default_token_cache_ttl")]
    #[builder(default = default_token_cache_ttl())]
    pub cache_ttl: u64,

    /// Clock skew tolerance in seconds (for timestamp validation)
    /// Note: Serde defaults to Some(60), builder defaults to None - use .clock_skew(60) for parity
    #[serde(default = "default_token_clock_skew")]
    pub clock_skew: Option<u64>,

    /// Maximum token age in seconds (from iat to now)
    /// Note: Serde defaults to Some(86400), builder defaults to None - use .max_age(86400) for
    /// parity
    #[serde(default = "default_token_max_age")]
    pub max_age: Option<u64>,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            cache_ttl: default_token_cache_ttl(),
            clock_skew: default_token_clock_skew(),
            max_age: default_token_max_age(),
        }
    }
}

impl TokenConfig {
    /// Validate token configuration
    pub fn validate(&self) -> Result<(), String> {
        // Warn if clock skew is too permissive (> 5 minutes)
        if let Some(skew) = self.clock_skew
            && skew > 300
        {
            tracing::warn!(
                clock_skew = %skew,
                "Clock skew tolerance is very high (> 5 minutes). \
                 This may allow expired tokens to be accepted. \
                 Recommended: 60 seconds or less."
            );
        }

        Ok(())
    }
}

/// Replication configuration for multi-region deployments
///
/// Enables replication of relationship data across multiple nodes and regions
/// for high availability and low-latency global access.
#[derive(Debug, Clone, Default, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct ReplicationConfig {
    /// Enable replication (default: false)
    #[serde(default)]
    #[builder(default)]
    pub enabled: bool,

    /// Replication strategy
    #[serde(default)]
    #[builder(default)]
    pub strategy: ReplicationStrategyConfig,

    /// Local region identifier (e.g., "us-west-1")
    #[serde(default)]
    #[builder(default)]
    pub local_region: String,

    /// Conflict resolution strategy
    #[serde(default)]
    #[builder(default)]
    pub conflict_resolution: ConflictResolutionConfig,

    /// Replication agent configuration
    #[serde(default)]
    #[builder(default)]
    pub agent: ReplicationAgentConfig,

    /// Region definitions
    #[serde(default)]
    #[builder(default)]
    pub regions: Vec<RegionConfig>,

    /// Replication targets: which regions each region replicates to
    /// Key: source region ID, Value: list of target region IDs
    #[serde(default)]
    #[builder(default)]
    pub replication_targets: std::collections::HashMap<String, Vec<String>>,
}

impl ReplicationConfig {
    /// Validate replication configuration
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.local_region.is_empty() {
            return Err("replication.local_region is required when replication is enabled".into());
        }

        // Validate that local region exists in regions list
        if !self.regions.iter().any(|r| r.id == self.local_region) {
            return Err(format!(
                "replication.local_region '{}' not found in regions list",
                self.local_region
            ));
        }

        // Validate replication targets reference valid regions
        for (source, targets) in &self.replication_targets {
            if !self.regions.iter().any(|r| &r.id == source) {
                return Err(format!(
                    "replication_targets source '{}' not found in regions list",
                    source
                ));
            }
            for target in targets {
                if !self.regions.iter().any(|r| &r.id == target) {
                    return Err(format!(
                        "replication_targets target '{}' not found in regions list",
                        target
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Replication strategy configuration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationStrategyConfig {
    /// All regions accept writes; changes replicate bidirectionally
    #[default]
    ActiveActive,
    /// One primary region accepts writes; other regions are read replicas
    PrimaryReplica,
    /// Multiple regions as primaries for different tenants/namespaces
    MultiMaster,
}

/// Conflict resolution strategy configuration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolutionConfig {
    /// Last write wins based on timestamp
    #[default]
    LastWriteWins,
    /// Region priority determines winner
    SourcePriority,
    /// Inserts always win over deletes
    InsertWins,
}

/// Replication agent configuration
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
pub struct ReplicationAgentConfig {
    /// Maximum retries for failed replications
    #[serde(default = "default_replication_max_retries")]
    #[builder(default = default_replication_max_retries())]
    pub max_retries: u32,

    /// Base retry delay in milliseconds
    #[serde(default = "default_replication_retry_delay_ms")]
    #[builder(default = default_replication_retry_delay_ms())]
    pub retry_delay_ms: u64,

    /// Maximum batch size for replication
    #[serde(default = "default_replication_batch_size")]
    #[builder(default = default_replication_batch_size())]
    pub batch_size: usize,

    /// Request timeout in seconds
    #[serde(default = "default_replication_request_timeout_secs")]
    #[builder(default = default_replication_request_timeout_secs())]
    pub request_timeout_secs: u64,

    /// Buffer size for pending changes
    #[serde(default = "default_replication_buffer_size")]
    #[builder(default = default_replication_buffer_size())]
    pub buffer_size: usize,
}

impl Default for ReplicationAgentConfig {
    fn default() -> Self {
        Self {
            max_retries: default_replication_max_retries(),
            retry_delay_ms: default_replication_retry_delay_ms(),
            batch_size: default_replication_batch_size(),
            request_timeout_secs: default_replication_request_timeout_secs(),
            buffer_size: default_replication_buffer_size(),
        }
    }
}

fn default_replication_max_retries() -> u32 {
    5
}

fn default_replication_retry_delay_ms() -> u64 {
    100
}

fn default_replication_batch_size() -> usize {
    100
}

fn default_replication_request_timeout_secs() -> u64 {
    10
}

fn default_replication_buffer_size() -> usize {
    10000
}

/// Region configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionConfig {
    /// Region identifier (e.g., "us-west-1")
    pub id: String,

    /// Human-readable region name
    #[serde(default)]
    pub name: String,

    /// Whether this region is the primary (for PrimaryReplica strategy)
    #[serde(default)]
    pub is_primary: bool,

    /// Zones within this region
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
}

/// Zone configuration within a region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    /// Zone identifier (e.g., "us-west-1a")
    pub id: String,

    /// Human-readable zone name
    #[serde(default)]
    pub name: String,

    /// Nodes within this zone
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
}

/// Node configuration within a zone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node identifier
    pub id: String,

    /// gRPC endpoint for this node (e.g., "http://inferadb-engine-1:8081")
    pub endpoint: String,
}

fn default_token_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_token_clock_skew() -> Option<u64> {
    Some(60) // 1 minute tolerance for clock differences
}

fn default_token_max_age() -> Option<u64> {
    Some(86400) // 24 hours maximum token age
}

impl Config {
    /// Validate configuration at startup
    ///
    /// This method performs comprehensive validation of all configuration values,
    /// catching errors early before they cause runtime failures.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate threads
        if self.threads == 0 {
            anyhow::bail!("threads must be greater than 0");
        }

        // Validate logging level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.to_lowercase().as_str()) {
            anyhow::bail!(
                "Invalid logging level: '{}'. Must be one of: {}",
                self.logging,
                valid_levels.join(", ")
            );
        }

        // Validate listen addresses are parseable
        self.listen.http.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "listen.http '{}' is not a valid socket address: {}",
                self.listen.http,
                e
            )
        })?;
        self.listen.grpc.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "listen.grpc '{}' is not a valid socket address: {}",
                self.listen.grpc,
                e
            )
        })?;

        // Validate storage backend
        match self.storage.as_str() {
            "memory" | "ledger" => {
                // Valid backends
            },
            "foundationdb" | "fdb" => {
                anyhow::bail!(
                    "FoundationDB storage backend has been removed. \
                     Please migrate to 'ledger' backend. \
                     See the PRD for migration instructions."
                );
            },
            _ => {
                anyhow::bail!(
                    "Unknown storage backend: '{}'. Valid options are 'memory' or 'ledger'.",
                    self.storage
                );
            },
        }

        // Validate Ledger configuration
        if self.storage == "ledger" {
            if self.ledger.endpoint.is_none() {
                anyhow::bail!("ledger.endpoint is required when using Ledger backend");
            }
            if self.ledger.client_id.is_none() {
                anyhow::bail!("ledger.client_id is required when using Ledger backend");
            }
            if self.ledger.namespace_id.is_none() {
                anyhow::bail!("ledger.namespace_id is required when using Ledger backend");
            }
            // Validate endpoint URL format
            let endpoint = self.ledger.endpoint.as_ref().unwrap();
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                anyhow::bail!(
                    "ledger.endpoint must start with http:// or https://, got: {}",
                    endpoint
                );
            }
        }

        // Validate token config
        self.token.validate().map_err(|e| anyhow::anyhow!(e))?;

        // Validate replication config
        self.replication.validate().map_err(|e| anyhow::anyhow!(e))?;

        // Validate cache TTL values are reasonable
        if self.token.cache_ttl == 0 {
            tracing::warn!("token.cache_ttl is 0. This will cause frequent JWKS fetches.");
        }
        if self.token.cache_ttl > 3600 {
            tracing::warn!(
                ttl = self.token.cache_ttl,
                "token.cache_ttl is very high (>1 hour). Consider using a lower TTL for security."
            );
        }

        Ok(())
    }

    /// Apply environment-aware defaults for storage backend.
    ///
    /// In development environment, if Ledger is the default but no Ledger configuration
    /// is provided, automatically fall back to memory storage for convenience.
    /// This allows `cargo run` to "just work" without requiring Ledger setup.
    ///
    /// In production or when Ledger configuration is explicitly provided,
    /// no changes are made and validation will enforce proper configuration.
    ///
    /// # Arguments
    ///
    /// * `environment` - The environment name (e.g., "development", "staging", "production")
    pub fn apply_environment_defaults(&mut self, environment: &str) {
        // Only apply in development environment
        if environment != "development" {
            return;
        }

        // If storage is ledger (the default) and no ledger config is provided,
        // fall back to memory for developer convenience
        if self.storage == "ledger"
            && self.ledger.endpoint.is_none()
            && self.ledger.client_id.is_none()
            && self.ledger.namespace_id.is_none()
        {
            tracing::info!(
                "Development mode: No Ledger configuration provided, using memory storage. \
                 Set storage='memory' explicitly or provide ledger config to suppress this message."
            );
            self.storage = "memory".to_string();
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: default_threads(),
            logging: default_logging(),
            listen: ListenConfig { http: default_http(), grpc: default_grpc() },
            storage: default_storage(),
            ledger: LedgerConfig::default(),
            cache: CacheConfig {
                enabled: default_cache_enabled(),
                capacity: default_cache_capacity(),
                ttl: default_cache_ttl(),
            },
            token: TokenConfig::default(),
            pem: None,
            replication: ReplicationConfig::default(),
        }
    }
}

/// Load configuration with layered precedence: defaults → file → env vars
///
/// This function implements a proper configuration hierarchy:
/// 1. Start with hardcoded defaults (via `#[serde(default)]` annotations)
/// 2. Override with values from config file (if file exists and properties are set)
/// 3. Override with environment variables (if env vars are set)
///
/// Each layer only overrides properties that are explicitly set, preserving
/// defaults for unspecified values.
///
/// ## Unified Configuration Format
///
/// The configuration file should use the nested format with an `engine:` section:
///
/// ```yaml
/// engine:
///   threads: 4
///   logging: "info"
///   listen:
///     http: "127.0.0.1:8080"
///   storage:
///     backend: "memory"
/// ```
///
/// Environment variables use the `INFERADB__ENGINE__` prefix:
/// - `INFERADB__ENGINE__THREADS=8`
/// - `INFERADB__ENGINE__LOGGING=debug`
/// - `INFERADB__ENGINE__LISTEN__HTTP=0.0.0.0:8080`
/// - `INFERADB__ENGINE__STORAGE__BACKEND=ledger`
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    // The config crate will use serde's #[serde(default)] annotations for defaults
    // Layer 1 (defaults) is handled by serde deserialization
    // Layer 2: Add file source (optional - only overrides if file exists)
    let builder = ConfigLoader::builder().add_source(File::from(path.as_ref()).required(false));

    // Layer 3: Add environment variables (highest precedence)
    // Use INFERADB__ENGINE__ prefix for the nested format
    let builder =
        builder.add_source(Environment::with_prefix("INFERADB").separator("__").try_parsing(true));

    let config = builder.build()?;

    // Deserialize as RootConfig and extract the engine section
    let root: RootConfig = config.try_deserialize()?;
    Ok(root.engine)
}

/// Load configuration with defaults
///
/// Convenience wrapper around `load()` that logs warnings but never panics.
/// Always returns a valid configuration, falling back to defaults if needed.
pub fn load_or_default<P: AsRef<Path>>(path: P) -> Config {
    match load(path.as_ref()) {
        Ok(config) => {
            tracing::info!("Configuration loaded successfully from {:?}", path.as_ref());
            config
        },
        Err(e) => {
            tracing::warn!(
                "Failed to load config from {:?}: {}. Using defaults with environment overrides.",
                path.as_ref(),
                e
            );

            // Even if file loading fails, try to apply env vars to defaults
            Config::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.threads > 0);
        assert_eq!(config.logging, "info");
        assert_eq!(config.listen.http, "0.0.0.0:8080");
        assert_eq!(config.listen.grpc, "0.0.0.0:8081");
        assert!(config.cache.enabled);
        // Default token cache TTL
        assert_eq!(config.token.cache_ttl, 300);
    }

    #[test]
    fn test_token_config_validation_high_clock_skew() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        // High clock skew should warn but not fail
        let config = TokenConfig { clock_skew: Some(600), ..Default::default() };
        assert!(config.validate().is_ok());
    }

    // === TDD Tests for bon Builder API ===

    #[test]
    fn test_cache_config_builder() {
        let built = CacheConfig::builder().enabled(true).capacity(10_000).ttl(60).build();
        assert!(built.enabled);
        assert_eq!(built.capacity, 10_000);
        assert_eq!(built.ttl, 60);
    }

    #[test]
    fn test_cache_config_builder_serde_equivalence() {
        // Verify builder with defaults matches serde deserialization with defaults
        let built = CacheConfig::builder().build();
        let parsed: CacheConfig = serde_json::from_str("{}").expect("parse empty json");
        assert_eq!(built.enabled, parsed.enabled);
        assert_eq!(built.capacity, parsed.capacity);
        assert_eq!(built.ttl, parsed.ttl);
    }

    #[test]
    fn test_token_config_builder() {
        // Note: For Option<T> fields, bon setters take T directly, not Option<T>
        let built = TokenConfig::builder().cache_ttl(600).clock_skew(120).max_age(3600).build();
        assert_eq!(built.cache_ttl, 600);
        assert_eq!(built.clock_skew, Some(120));
        assert_eq!(built.max_age, Some(3600));
    }

    #[test]
    fn test_token_config_builder_serde_equivalence() {
        // Builder with explicit values to match serde defaults for Option fields
        let built = TokenConfig::builder()
            .clock_skew(60) // serde default is Some(60)
            .max_age(86400) // serde default is Some(86400)
            .build();
        let parsed: TokenConfig = serde_json::from_str("{}").expect("parse empty json");
        assert_eq!(built.cache_ttl, parsed.cache_ttl);
        assert_eq!(built.clock_skew, parsed.clock_skew);
        assert_eq!(built.max_age, parsed.max_age);
    }

    #[test]
    fn test_listen_config_builder() {
        let built = ListenConfig::builder().http("127.0.0.1:9000").grpc("127.0.0.1:9001").build();
        assert_eq!(built.http, "127.0.0.1:9000");
        assert_eq!(built.grpc, "127.0.0.1:9001");
    }

    #[test]
    fn test_listen_config_builder_serde_equivalence() {
        let built = ListenConfig::builder().build();
        let parsed: ListenConfig = serde_json::from_str("{}").expect("parse empty json");
        assert_eq!(built.http, parsed.http);
        assert_eq!(built.grpc, parsed.grpc);
    }

    #[test]
    fn test_ledger_config_builder() {
        // Note: For Option<T> fields, bon setters take T directly, not Option<T>
        let built = LedgerConfig::builder()
            .endpoint("http://localhost:50051".to_owned())
            .client_id("engine-1".to_owned())
            .namespace_id(42)
            .vault_id(1)
            .build();
        assert_eq!(built.endpoint, Some("http://localhost:50051".to_owned()));
        assert_eq!(built.client_id, Some("engine-1".to_owned()));
        assert_eq!(built.namespace_id, Some(42));
        assert_eq!(built.vault_id, Some(1));
    }

    #[test]
    fn test_ledger_config_builder_defaults() {
        // All fields optional with None defaults
        let built = LedgerConfig::builder().build();
        assert_eq!(built.endpoint, None);
        assert_eq!(built.client_id, None);
        assert_eq!(built.namespace_id, None);
        assert_eq!(built.vault_id, None);
    }

    #[test]
    fn test_replication_agent_config_builder() {
        let built = ReplicationAgentConfig::builder()
            .max_retries(10)
            .retry_delay_ms(200)
            .batch_size(50)
            .request_timeout_secs(30)
            .buffer_size(5000)
            .build();
        assert_eq!(built.max_retries, 10);
        assert_eq!(built.retry_delay_ms, 200);
        assert_eq!(built.batch_size, 50);
        assert_eq!(built.request_timeout_secs, 30);
        assert_eq!(built.buffer_size, 5000);
    }

    #[test]
    fn test_replication_agent_config_builder_serde_equivalence() {
        let built = ReplicationAgentConfig::builder().build();
        let parsed: ReplicationAgentConfig = serde_json::from_str("{}").expect("parse empty json");
        assert_eq!(built.max_retries, parsed.max_retries);
        assert_eq!(built.retry_delay_ms, parsed.retry_delay_ms);
        assert_eq!(built.batch_size, parsed.batch_size);
        assert_eq!(built.request_timeout_secs, parsed.request_timeout_secs);
        assert_eq!(built.buffer_size, parsed.buffer_size);
    }

    #[test]
    fn test_replication_config_builder() {
        let agent = ReplicationAgentConfig::builder().max_retries(3).build();
        let built = ReplicationConfig::builder()
            .enabled(true)
            .local_region("us-west-1")
            .agent(agent)
            .build();
        assert!(built.enabled);
        assert_eq!(built.local_region, "us-west-1");
        assert_eq!(built.agent.max_retries, 3);
    }

    #[test]
    fn test_nested_config_builder_composition() {
        // Demonstrates nested builder usage
        let config = Config::builder()
            .cache(CacheConfig::builder().enabled(true).capacity(5000).build())
            .token(TokenConfig::builder().cache_ttl(600).build())
            .listen(ListenConfig::builder().http("0.0.0.0:9000").build())
            .replication(
                ReplicationConfig::builder()
                    .enabled(true)
                    .agent(ReplicationAgentConfig::builder().max_retries(10).build())
                    .build(),
            )
            .build();
        assert!(config.cache.enabled);
        assert_eq!(config.cache.capacity, 5000);
        assert_eq!(config.token.cache_ttl, 600);
        assert_eq!(config.listen.http, "0.0.0.0:9000");
        assert!(config.replication.enabled);
        assert_eq!(config.replication.agent.max_retries, 10);
    }

    #[test]
    fn test_config_builder_with_defaults() {
        let built = Config::builder().build();
        let default = Config::default();
        // Builder defaults should match Default trait implementation
        assert_eq!(built.logging, default.logging);
        assert_eq!(built.listen.http, default.listen.http);
        assert_eq!(built.listen.grpc, default.listen.grpc);
        assert_eq!(built.cache.enabled, default.cache.enabled);
        assert_eq!(built.cache.capacity, default.cache.capacity);
        assert_eq!(built.cache.ttl, default.cache.ttl);
        assert_eq!(built.storage, default.storage);
    }
}
