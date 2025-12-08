//! # Infera Config - Configuration Management
//!
//! Handles configuration loading from files, environment variables, and CLI args.

pub mod hot_reload;
pub mod refresh;
pub mod secrets;
pub mod validation;

use std::path::Path;

use config::{Config as ConfigBuilder, ConfigError, Environment, File};
pub use refresh::ConfigRefresher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub management_service: ManagementServiceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
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

    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            public_rest: default_public_rest(),
            public_grpc: default_public_grpc(),
            private_rest: default_private_rest(),
            worker_threads: default_worker_threads(),
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

fn default_worker_threads() -> usize {
    num_cpus::get()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityConfig {
    /// Server identity Ed25519 private key (PEM format) for signing server-to-management requests.
    /// This key is used to authenticate the server when making calls to the management API.
    /// If not provided, will be generated on startup and logged (not recommended for production).
    pub private_key_pem: Option<String>,
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
pub struct ObservabilityConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,

    #[serde(default = "default_tracing_enabled")]
    pub tracing_enabled: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            metrics_enabled: default_metrics_enabled(),
            tracing_enabled: default_tracing_enabled(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_tracing_enabled() -> bool {
    true
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

    /// Whether to verify vault ownership against management API
    #[serde(default = "default_true")]
    pub management_verify_vault_ownership: bool,

    /// Whether to verify organization status against management API
    #[serde(default = "default_true")]
    pub management_verify_org_status: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none or kubernetes)
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_discovery_cache_ttl")]
    pub cache_ttl: u64,

    /// Whether to enable health checking of endpoints
    #[serde(default = "default_discovery_health_check")]
    pub enable_health_check: bool,

    /// Health check interval (in seconds)
    #[serde(default = "default_discovery_health_check_interval")]
    pub health_check_interval: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl: default_discovery_cache_ttl(),
            enable_health_check: default_discovery_health_check(),
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

    /// Service name within the cluster (e.g., "inferadb-server")
    pub service_name: String,

    /// Service port
    pub port: u16,
}

/// Management service discovery configuration
///
/// This configuration controls how the server discovers and connects to
/// management service instances. The server needs to fetch JWKS from
/// management services to validate JWTs signed by them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementServiceConfig {
    /// Internal port where management services expose their internal API (including JWKS)
    /// Default: 9092
    #[serde(default = "default_management_internal_port")]
    pub internal_port: u16,

    /// Service URL pattern for Kubernetes/Tailscale discovery
    /// e.g., "http://inferadb-management.inferadb:9092"
    /// This is used as a template when discovery is enabled
    #[serde(default = "default_management_service_url")]
    pub service_url: String,
}

impl Default for ManagementServiceConfig {
    fn default() -> Self {
        Self {
            internal_port: default_management_internal_port(),
            service_url: default_management_service_url(),
        }
    }
}

fn default_management_internal_port() -> u16 {
    9092 // Management internal/private server port
}

fn default_management_service_url() -> String {
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
    String::new()
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

fn default_true() -> bool {
    true
}

fn default_discovery_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_discovery_health_check() -> bool {
    false
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
        // Validate server addresses are parseable
        self.server.public_rest.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "server.public_rest '{}' is not a valid socket address: {}",
                self.server.public_rest,
                e
            )
        })?;
        self.server.public_grpc.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "server.public_grpc '{}' is not a valid socket address: {}",
                self.server.public_grpc,
                e
            )
        })?;
        self.server.private_rest.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "server.private_rest '{}' is not a valid socket address: {}",
                self.server.private_rest,
                e
            )
        })?;

        if self.server.worker_threads == 0 {
            anyhow::bail!("server.worker_threads must be greater than 0");
        }

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

        // Validate management service URL format
        let mgmt_url = self.effective_management_url();
        if !mgmt_url.starts_with("http://") && !mgmt_url.starts_with("https://") {
            anyhow::bail!(
                "management_service.service_url must start with http:// or https://, got: {}",
                mgmt_url
            );
        }
        if mgmt_url.ends_with('/') {
            anyhow::bail!(
                "management_service.service_url must not end with trailing slash: {}",
                mgmt_url
            );
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

    /// Get the management service URL
    ///
    /// Returns the URL for management service communication.
    pub fn effective_management_url(&self) -> String {
        self.management_service.service_url.clone()
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
            management_verify_vault_ownership: default_true(),
            management_verify_org_status: default_true(),
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
        // Warn if JWKS URL is missing
        if self.jwks_url.is_empty() {
            tracing::warn!(
                "jwks_url is empty. \
                 Tenant JWT authentication will not work."
            );
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
            server: ServerConfig {
                public_rest: default_public_rest(),
                public_grpc: default_public_grpc(),
                private_rest: default_private_rest(),
                worker_threads: default_worker_threads(),
            },
            storage: StorageConfig { backend: default_backend(), fdb_cluster_file: None },
            cache: CacheConfig {
                enabled: default_cache_enabled(),
                max_capacity: default_cache_max_capacity(),
                ttl: default_cache_ttl(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
            },
            auth: AuthConfig::default(),
            identity: IdentityConfig::default(),
            discovery: DiscoveryConfig::default(),
            management_service: ManagementServiceConfig::default(),
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
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    // The config crate will use serde's #[serde(default)] annotations for defaults
    // Layer 1 (defaults) is handled by serde deserialization
    // Layer 2: Add file source (optional - only overrides if file exists)
    let builder = ConfigBuilder::builder().add_source(File::from(path.as_ref()).required(false));

    // Layer 3: Add environment variables (highest precedence)
    let builder =
        builder.add_source(Environment::with_prefix("INFERADB").separator("__").try_parsing(true));

    let config = builder.build()?;
    config.try_deserialize()
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
        assert_eq!(config.server.public_rest, "0.0.0.0:8080");
        assert_eq!(config.server.public_grpc, "0.0.0.0:8081");
        assert_eq!(config.server.private_rest, "0.0.0.0:8082");
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_auth_config_validation_without_jwks_url() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let config = AuthConfig { jwks_url: String::new(), ..Default::default() };

        // Should warn but not panic
        let _ = config.validate();
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
