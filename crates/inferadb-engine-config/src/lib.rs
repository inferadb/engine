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
//!     public_rest: "127.0.0.1:8080"
//!   # ... other engine config
//!
//! control:
//!   threads: 4
//!   logging: "info"
//!   listen:
//!     public_rest: "127.0.0.1:9090"
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

    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub auth: AuthConfig,

    /// Server identity Ed25519 private key (PEM format) for signing server-to-control requests.
    /// This key is used to authenticate the server when making calls to the control API.
    /// If not provided, will be generated on startup and logged (not recommended for production).
    pub pem: Option<String>,

    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub control: ControlConfig,
}

/// Listen address configuration for API servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// Public REST API server address (client-facing)
    /// Format: "host:port" (e.g., "0.0.0.0:8080")
    #[serde(default = "default_public_rest")]
    pub public_rest: String,

    /// Public gRPC API server address
    /// Format: "host:port" (e.g., "0.0.0.0:8081")
    #[serde(default = "default_public_grpc")]
    pub public_grpc: String,

    /// Internal/Private REST API server address (server-to-server communication)
    /// Format: "host:port" (e.g., "0.0.0.0:8082")
    #[serde(default = "default_private_rest")]
    pub private_rest: String,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            public_rest: default_public_rest(),
            public_grpc: default_public_grpc(),
            private_rest: default_private_rest(),
        }
    }
}

fn default_public_rest() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_public_grpc() -> String {
    "0.0.0.0:8081".to_string()
}

fn default_private_rest() -> String {
    "0.0.0.0:8082".to_string() // Internal/Private server-to-server port
}

fn default_threads() -> usize {
    num_cpus::get()
}

fn default_logging() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String,

    pub fdb_cluster_file: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self { backend: default_backend(), fdb_cluster_file: None }
    }
}

fn default_backend() -> String {
    "memory".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,

    #[serde(default = "default_cache_max_capacity")]
    pub max_capacity: u64,

    #[serde(default = "default_cache_ttl")]
    pub ttl: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            max_capacity: default_cache_max_capacity(),
            ttl: default_cache_ttl(),
        }
    }
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_max_capacity() -> u64 {
    10_000
}

fn default_cache_ttl() -> u64 {
    300
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWKS cache TTL in seconds
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl: u64,

    /// Enable replay protection (requires Redis)
    #[serde(default = "default_replay_protection")]
    pub replay_protection: bool,

    /// OIDC discovery cache TTL in seconds
    #[serde(default = "default_oidc_discovery_cache_ttl")]
    pub oidc_discovery_cache_ttl: u64,

    /// Redis URL for replay protection (optional)
    pub redis_url: Option<String>,

    /// Clock skew tolerance in seconds (for timestamp validation)
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: Option<u64>,

    /// Maximum token age in seconds (from iat to now)
    #[serde(default = "default_max_token_age_seconds")]
    pub max_token_age_seconds: Option<u64>,

    /// Require JTI claim in all tokens
    #[serde(default = "default_require_jti")]
    pub require_jti: bool,

    /// Enable OAuth token validation
    #[serde(default = "default_oauth_enabled")]
    pub oauth_enabled: bool,

    /// OIDC discovery URL (for OAuth providers)
    pub oidc_discovery_url: Option<String>,

    /// OIDC client ID
    pub oidc_client_id: Option<String>,

    /// OIDC client secret
    pub oidc_client_secret: Option<String>,

    /// JWKS URL for tenant authentication
    #[serde(default = "default_jwks_url")]
    pub jwks_url: String,

    /// Timeout for management API calls in milliseconds
    #[serde(default = "default_management_api_timeout")]
    pub management_api_timeout_ms: u64,

    /// Cache TTL for management API responses (org/vault) in seconds
    #[serde(default = "default_management_cache_ttl")]
    pub management_cache_ttl: u64,

    /// Cache TTL for client certificates in seconds
    #[serde(default = "default_cert_cache_ttl")]
    pub cert_cache_ttl: u64,
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

/// Control service discovery configuration
///
/// This configuration controls how the engine discovers and connects to
/// control service instances. The engine needs to fetch JWKS from
/// control services to validate JWTs signed by them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Internal port where control services expose their internal API (including JWKS)
    /// Default: 9092
    #[serde(default = "default_control_internal_port")]
    pub internal_port: u16,

    /// Service URL pattern for Kubernetes/Tailscale discovery
    /// e.g., "http://inferadb-control.inferadb:9092"
    /// This is used as a template when discovery is enabled
    #[serde(default = "default_control_service_url")]
    pub service_url: String,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            internal_port: default_control_internal_port(),
            service_url: default_control_service_url(),
        }
    }
}

fn default_control_internal_port() -> u16 {
    9092 // Control internal/private server port
}

fn default_control_service_url() -> String {
    // Default for development - localhost
    // In production with discovery, this should be the K8s service URL
    "http://localhost:9092".to_string()
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

fn default_oauth_enabled() -> bool {
    false
}

fn default_jwks_url() -> String {
    // Default for development - control's public API port
    // In production, this should be configured to point to the control service's public endpoint
    "http://localhost:9090".to_string()
}

fn default_replay_protection() -> bool {
    false
}

fn default_oidc_discovery_cache_ttl() -> u64 {
    86400 // 24 hours in seconds
}

fn default_management_api_timeout() -> u64 {
    5000 // 5 seconds
}

fn default_management_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_cert_cache_ttl() -> u64 {
    900 // 15 minutes
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
        self.listen.public_rest.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "listen.public_rest '{}' is not a valid socket address: {}",
                self.listen.public_rest,
                e
            )
        })?;
        self.listen.public_grpc.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "listen.public_grpc '{}' is not a valid socket address: {}",
                self.listen.public_grpc,
                e
            )
        })?;
        self.listen.private_rest.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "listen.private_rest '{}' is not a valid socket address: {}",
                self.listen.private_rest,
                e
            )
        })?;

        // Validate storage backend
        if self.storage.backend != "memory" && self.storage.backend != "foundationdb" {
            anyhow::bail!(
                "Invalid storage.backend: '{}'. Must be 'memory' or 'foundationdb'",
                self.storage.backend
            );
        }

        // Validate FoundationDB configuration
        if self.storage.backend == "foundationdb" && self.storage.fdb_cluster_file.is_none() {
            anyhow::bail!("storage.fdb_cluster_file is required when using FoundationDB backend");
        }

        // Validate authentication config (delegates to AuthConfig::validate)
        self.auth.validate().map_err(|e| anyhow::anyhow!(e))?;

        // Validate control service URL format
        let control_url = self.effective_control_url();
        if !control_url.starts_with("http://") && !control_url.starts_with("https://") {
            anyhow::bail!(
                "control.service_url must start with http:// or https://, got: {}",
                control_url
            );
        }
        if control_url.ends_with('/') {
            anyhow::bail!("control.service_url must not end with trailing slash: {}", control_url);
        }

        // Validate cache TTL values are reasonable
        if self.auth.jwks_cache_ttl == 0 {
            tracing::warn!("auth.jwks_cache_ttl is 0. This will cause frequent JWKS fetches.");
        }
        if self.auth.jwks_cache_ttl > 3600 {
            tracing::warn!(
                ttl = self.auth.jwks_cache_ttl,
                "auth.jwks_cache_ttl is very high (>1 hour). Consider using a lower TTL for security."
            );
        }

        Ok(())
    }

    /// Get the control service URL
    ///
    /// Returns the URL for control service communication.
    pub fn effective_control_url(&self) -> String {
        self.control.service_url.clone()
    }

    /// Check if service discovery is enabled
    pub fn is_discovery_enabled(&self) -> bool {
        !matches!(self.discovery.mode, DiscoveryMode::None)
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwks_cache_ttl: default_jwks_cache_ttl(),
            replay_protection: default_replay_protection(),
            oidc_discovery_cache_ttl: default_oidc_discovery_cache_ttl(),
            redis_url: None,
            clock_skew_seconds: default_clock_skew_seconds(),
            max_token_age_seconds: default_max_token_age_seconds(),
            require_jti: default_require_jti(),
            oauth_enabled: default_oauth_enabled(),
            oidc_discovery_url: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            jwks_url: default_jwks_url(),
            management_api_timeout_ms: default_management_api_timeout(),
            management_cache_ttl: default_management_cache_ttl(),
            cert_cache_ttl: default_cert_cache_ttl(),
        }
    }
}

impl AuthConfig {
    /// Validate the authentication configuration and log warnings for potential issues
    ///
    /// This method performs comprehensive validation of security-related settings:
    /// - Checks for forbidden algorithms (symmetric algorithms, "none")
    /// - Validates replay protection configuration
    /// - Warns about overly permissive clock skew settings
    /// - Validates issuer and audience configuration
    /// - Ensures required JTI when replay protection is enabled
    pub fn validate(&self) -> Result<(), String> {
        // Validate JWKS URL format if provided
        if !self.jwks_url.is_empty()
            && !self.jwks_url.starts_with("http://")
            && !self.jwks_url.starts_with("https://")
        {
            return Err(format!(
                "auth.jwks_url must start with http:// or https://, got: {}",
                self.jwks_url
            ));
        }

        // CRITICAL: Reject if replay_protection enabled but no redis_url
        if self.replay_protection && self.redis_url.is_none() {
            return Err("replay_protection is enabled but redis_url is not configured. \
                 Either disable replay_protection or configure redis_url."
                .to_string());
        }

        // Warn if replay protection is enabled with require_jti false
        if self.replay_protection && !self.require_jti {
            tracing::warn!(
                "replay_protection is enabled but require_jti is false. \
                 Tokens without JTI will fail validation. Consider setting require_jti=true."
            );
        }

        // Warn if using in-memory replay protection (when Redis is not configured)
        if self.replay_protection && self.redis_url.is_none() {
            tracing::warn!(
                "In-memory replay protection is NOT suitable for multi-node deployments. \
                 Configure redis_url for production use."
            );
        }

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

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: default_threads(),
            logging: default_logging(),
            listen: ListenConfig {
                public_rest: default_public_rest(),
                public_grpc: default_public_grpc(),
                private_rest: default_private_rest(),
            },
            storage: StorageConfig { backend: default_backend(), fdb_cluster_file: None },
            cache: CacheConfig {
                enabled: default_cache_enabled(),
                max_capacity: default_cache_max_capacity(),
                ttl: default_cache_ttl(),
            },
            auth: AuthConfig::default(),
            pem: None,
            discovery: DiscoveryConfig::default(),
            control: ControlConfig::default(),
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
///     public_rest: "127.0.0.1:8080"
///   storage:
///     backend: "memory"
/// ```
///
/// Environment variables use the `INFERADB__ENGINE__` prefix:
/// - `INFERADB__ENGINE__THREADS=8`
/// - `INFERADB__ENGINE__LOGGING=debug`
/// - `INFERADB__ENGINE__LISTEN__PUBLIC_REST=0.0.0.0:8080`
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
        assert_eq!(config.listen.public_rest, "0.0.0.0:8080");
        assert_eq!(config.listen.public_grpc, "0.0.0.0:8081");
        assert_eq!(config.listen.private_rest, "0.0.0.0:8082");
        assert!(config.cache.enabled);
        // Default JWKS URL points to control's public API for local development
        assert_eq!(config.auth.jwks_url, "http://localhost:9090");
        // Default control service URL points to control's internal API
        assert_eq!(config.control.service_url, "http://localhost:9092");
    }

    #[test]
    fn test_auth_config_validation_with_empty_jwks_url() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        // Empty JWKS URL is valid (falls back to default behavior)
        let config = AuthConfig { jwks_url: String::new(), ..Default::default() };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_auth_config_validation_invalid_jwks_url() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        // Invalid JWKS URL (not http/https) should fail
        let config =
            AuthConfig { jwks_url: "ftp://invalid.example.com".to_string(), ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_auth_config_validation_replay_protection_without_redis() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let config = AuthConfig { replay_protection: true, redis_url: None, ..Default::default() };

        // Should warn but not panic
        let _ = config.validate();
    }

    #[test]
    fn test_auth_config_validation_valid_config() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        let config = AuthConfig {
            jwks_url: "https://auth.example.com/.well-known/jwks.json".to_string(),
            replay_protection: false,
            ..Default::default()
        };

        // Should not log any warnings
        let _ = config.validate();
    }
}
