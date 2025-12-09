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

pub mod hot_reload;
pub mod refresh;
pub mod secrets;
pub mod validation;

use std::path::Path;

use config::{Config as ConfigBuilder, ConfigError, Environment, File};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Number of worker threads for the async runtime
    #[serde(default = "default_threads")]
    pub threads: usize,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_logging")]
    pub logging: String,

    /// Server identity Ed25519 private key (PEM format) for signing server-to-control requests.
    /// This key is used to authenticate the server when making calls to the control API.
    /// If not provided, will be generated on startup and logged (not recommended for production).
    pub pem: Option<String>,

    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default = "default_storage")]
    pub storage: String,
    #[serde(default)]
    pub foundationdb: FoundationDbConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub token: TokenConfig,
    #[serde(default)]
    pub replay_protection: ReplayProtectionConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub mesh: MeshConfig,
}

/// Listen address configuration for API servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// Client-facing HTTP/REST API server address
    /// Format: "host:port" (e.g., "0.0.0.0:8080")
    #[serde(default = "default_http")]
    pub http: String,

    /// Client-facing gRPC API server address
    /// Format: "host:port" (e.g., "0.0.0.0:8081")
    #[serde(default = "default_grpc")]
    pub grpc: String,

    /// Service mesh / inter-service communication address
    /// Used for JWKS endpoints, metrics, cache invalidation webhooks
    /// Format: "host:port" (e.g., "0.0.0.0:8082")
    #[serde(default = "default_mesh")]
    pub mesh: String,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self { http: default_http(), grpc: default_grpc(), mesh: default_mesh() }
    }
}

fn default_http() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_grpc() -> String {
    "0.0.0.0:8081".to_string()
}

fn default_mesh() -> String {
    "0.0.0.0:8082".to_string()
}

fn default_threads() -> usize {
    num_cpus::get()
}

fn default_logging() -> String {
    "info".to_string()
}

fn default_storage() -> String {
    "memory".to_string()
}

/// FoundationDB configuration (only used when storage = "foundationdb")
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FoundationDbConfig {
    /// FoundationDB cluster file path
    /// e.g., "/etc/foundationdb/fdb.cluster"
    pub cluster_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,

    #[serde(default = "default_cache_capacity")]
    pub capacity: u64,

    #[serde(default = "default_cache_ttl")]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// JWKS cache TTL in seconds
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl: u64,

    /// Clock skew tolerance in seconds (for timestamp validation)
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: Option<u64>,

    /// Maximum token age in seconds (from iat to now)
    #[serde(default = "default_max_token_age_seconds")]
    pub max_token_age_seconds: Option<u64>,

    /// Require JTI claim in all tokens
    #[serde(default = "default_require_jti")]
    pub require_jti: bool,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            jwks_cache_ttl: default_jwks_cache_ttl(),
            clock_skew_seconds: default_clock_skew_seconds(),
            max_token_age_seconds: default_max_token_age_seconds(),
            require_jti: default_require_jti(),
        }
    }
}

impl TokenConfig {
    /// Validate token configuration
    pub fn validate(&self) -> Result<(), String> {
        // Warn if clock skew is too permissive (> 5 minutes)
        if let Some(skew) = self.clock_skew_seconds {
            if skew > 300 {
                tracing::warn!(
                    clock_skew = %skew,
                    "Clock skew tolerance is very high (> 5 minutes). \
                     This may allow expired tokens to be accepted. \
                     Recommended: 60 seconds or less."
                );
            }
        }

        Ok(())
    }
}

/// Replay protection configuration
///
/// Optional feature to prevent token replay attacks. Requires Redis
/// for multi-node deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayProtectionConfig {
    /// Enable replay protection
    #[serde(default = "default_replay_protection")]
    pub enabled: bool,

    /// Redis URL for replay protection (required when enabled)
    pub redis_url: Option<String>,
}

impl Default for ReplayProtectionConfig {
    fn default() -> Self {
        Self { enabled: default_replay_protection(), redis_url: None }
    }
}

impl ReplayProtectionConfig {
    /// Validate replay protection configuration
    pub fn validate(&self, require_jti: bool) -> Result<(), String> {
        // CRITICAL: Reject if enabled but no redis_url
        if self.enabled && self.redis_url.is_none() {
            return Err(
                "replay_protection.enabled is true but replay_protection.redis_url is not configured. \
                 Either disable replay_protection or configure redis_url."
                    .to_string(),
            );
        }

        // Warn if replay protection is enabled with require_jti false
        if self.enabled && !require_jti {
            tracing::warn!(
                "replay_protection.enabled is true but jwt.require_jti is false. \
                 Tokens without JTI will fail validation. Consider setting jwt.require_jti=true."
            );
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none or kubernetes)
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_discovery_cache_ttl")]
    pub cache_ttl: u64,

    /// Health check interval (in seconds)
    #[serde(default = "default_discovery_health_check_interval")]
    pub health_check_interval: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl: default_discovery_cache_ttl(),
            health_check_interval: default_discovery_health_check_interval(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum DiscoveryMode {
    /// No service discovery - use service URL directly
    #[default]
    None,
    /// Kubernetes service discovery - resolve to pod IPs
    Kubernetes,
    /// Tailscale mesh networking for multi-region discovery
    Tailscale {
        /// Local cluster name (e.g., "us-west-1")
        local_cluster: String,
        /// Remote clusters to discover across
        #[serde(default)]
        remote_clusters: Vec<RemoteCluster>,
    },
}

/// Remote cluster configuration for Tailscale mesh networking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCluster {
    /// Cluster name (e.g., "eu-west-1", "ap-southeast-1")
    pub name: String,

    /// Tailscale domain for this cluster (e.g., "eu-west-1.ts.net")
    pub tailscale_domain: String,

    /// Service name within the cluster (e.g., "inferadb-engine")
    pub service_name: String,

    /// Service port
    pub port: u16,
}

/// Service mesh configuration for control communication
///
/// This configuration controls how the engine discovers and connects to
/// control service instances. The engine needs to communicate with control
/// services for JWKS fetching, org/vault validation, and certificate verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Base URL for control service
    /// e.g., "http://inferadb-control.inferadb:9092" for K8s
    /// or "http://localhost:9092" for development
    #[serde(default = "default_mesh_url")]
    pub url: String,

    /// Timeout for mesh API calls in milliseconds
    #[serde(default = "default_mesh_timeout")]
    pub timeout: u64,

    /// Cache TTL for mesh API responses (org/vault lookups) in seconds
    #[serde(default = "default_mesh_cache_ttl")]
    pub cache_ttl: u64,

    /// Cache TTL for client certificates in seconds
    #[serde(default = "default_mesh_cert_cache_ttl")]
    pub cert_cache_ttl: u64,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            url: default_mesh_url(),
            timeout: default_mesh_timeout(),
            cache_ttl: default_mesh_cache_ttl(),
            cert_cache_ttl: default_mesh_cert_cache_ttl(),
        }
    }
}

impl MeshConfig {
    /// Validate mesh service configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate URL format
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(format!(
                "mesh.url must start with http:// or https://, got: {}",
                self.url
            ));
        }
        if self.url.ends_with('/') {
            return Err(format!(
                "mesh.url must not end with trailing slash: {}",
                self.url
            ));
        }

        Ok(())
    }
}

fn default_mesh_url() -> String {
    // Default for development - localhost
    // In production with discovery, this should be the K8s service URL
    "http://localhost:9092".to_string()
}

fn default_mesh_timeout() -> u64 {
    5000 // 5 seconds (in milliseconds)
}

fn default_mesh_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_mesh_cert_cache_ttl() -> u64 {
    900 // 15 minutes
}

fn default_jwks_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_clock_skew_seconds() -> Option<u64> {
    Some(60) // 1 minute tolerance for clock differences
}

fn default_max_token_age_seconds() -> Option<u64> {
    Some(86400) // 24 hours maximum token age
}

fn default_require_jti() -> bool {
    false // Optional by default, but required when replay_protection is enabled
}

fn default_replay_protection() -> bool {
    false
}

fn default_discovery_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_discovery_health_check_interval() -> u64 {
    30 // 30 seconds
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
            anyhow::anyhow!("listen.http '{}' is not a valid socket address: {}", self.listen.http, e)
        })?;
        self.listen.grpc.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!("listen.grpc '{}' is not a valid socket address: {}", self.listen.grpc, e)
        })?;
        self.listen.mesh.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!("listen.mesh '{}' is not a valid socket address: {}", self.listen.mesh, e)
        })?;

        // Validate storage backend
        if self.storage != "memory" && self.storage != "foundationdb" {
            anyhow::bail!(
                "Invalid storage: '{}'. Must be 'memory' or 'foundationdb'",
                self.storage
            );
        }

        // Validate FoundationDB configuration
        if self.storage == "foundationdb" && self.foundationdb.cluster_file.is_none() {
            anyhow::bail!("foundationdb.cluster_file is required when using FoundationDB backend");
        }

        // Validate token config
        self.token.validate().map_err(|e| anyhow::anyhow!(e))?;

        // Validate replay protection config
        self.replay_protection
            .validate(self.token.require_jti)
            .map_err(|e| anyhow::anyhow!(e))?;

        // Validate mesh service config
        self.mesh.validate().map_err(|e| anyhow::anyhow!(e))?;

        // Validate cache TTL values are reasonable
        if self.token.jwks_cache_ttl == 0 {
            tracing::warn!("token.jwks_cache_ttl is 0. This will cause frequent JWKS fetches.");
        }
        if self.token.jwks_cache_ttl > 3600 {
            tracing::warn!(
                ttl = self.token.jwks_cache_ttl,
                "token.jwks_cache_ttl is very high (>1 hour). Consider using a lower TTL for security."
            );
        }

        Ok(())
    }

    /// Get the mesh service URL
    ///
    /// Returns the URL for control service communication.
    pub fn effective_mesh_url(&self) -> String {
        self.mesh.url.clone()
    }

    /// Check if service discovery is enabled
    pub fn is_discovery_enabled(&self) -> bool {
        !matches!(self.discovery.mode, DiscoveryMode::None)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: default_threads(),
            logging: default_logging(),
            listen: ListenConfig { http: default_http(), grpc: default_grpc(), mesh: default_mesh() },
            storage: default_storage(),
            foundationdb: FoundationDbConfig::default(),
            cache: CacheConfig {
                enabled: default_cache_enabled(),
                capacity: default_cache_capacity(),
                ttl: default_cache_ttl(),
            },
            token: TokenConfig::default(),
            replay_protection: ReplayProtectionConfig::default(),
            pem: None,
            discovery: DiscoveryConfig::default(),
            mesh: MeshConfig::default(),
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
/// - `INFERADB__ENGINE__STORAGE__BACKEND=foundationdb`
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    // The config crate will use serde's #[serde(default)] annotations for defaults
    // Layer 1 (defaults) is handled by serde deserialization
    // Layer 2: Add file source (optional - only overrides if file exists)
    let builder = ConfigBuilder::builder().add_source(File::from(path.as_ref()).required(false));

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
        assert_eq!(config.listen.mesh, "0.0.0.0:8082");
        assert!(config.cache.enabled);
        // Default mesh service URL points to control's internal API
        assert_eq!(config.mesh.url, "http://localhost:9092");
        // Default token cache TTL
        assert_eq!(config.token.jwks_cache_ttl, 300);
    }

    #[test]
    fn test_token_config_validation_high_clock_skew() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        // High clock skew should warn but not fail
        let config = TokenConfig { clock_skew_seconds: Some(600), ..Default::default() };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_replay_protection_validation_without_redis() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let config = ReplayProtectionConfig { enabled: true, redis_url: None };

        // Should fail without redis_url
        assert!(config.validate(false).is_err());
    }

    #[test]
    fn test_replay_protection_validation_with_redis() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let config = ReplayProtectionConfig {
            enabled: true,
            redis_url: Some("redis://localhost:6379".to_string()),
        };

        // Should succeed with redis_url
        assert!(config.validate(true).is_ok());
    }

    #[test]
    fn test_mesh_config_validation_invalid_url() {
        let config = MeshConfig {
            url: "ftp://invalid.example.com".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_mesh_config_validation_trailing_slash() {
        let config = MeshConfig {
            url: "http://localhost:9092/".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_mesh_config_validation_valid() {
        let config = MeshConfig::default();
        assert!(config.validate().is_ok());
    }
}
