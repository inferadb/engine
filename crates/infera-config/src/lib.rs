//! # Infera Config - Configuration Management
//!
//! Handles configuration loading from files, environment variables, and CLI args.

pub mod hot_reload;
pub mod refresh;
pub mod secrets;
pub mod validation;

use std::path::{Path, PathBuf};

use config::{Config as ConfigBuilder, ConfigError, Environment, File};
pub use refresh::ConfigRefresher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub multi_tenancy: MultiTenancyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    // Public server (client-facing)
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    // Internal server (server-to-server communication)
    #[serde(default = "default_internal_host")]
    pub internal_host: String,

    #[serde(default = "default_internal_port")]
    pub internal_port: u16,

    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            internal_host: default_internal_host(),
            internal_port: default_internal_port(),
            worker_threads: default_worker_threads(),
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_internal_host() -> String {
    "0.0.0.0".to_string() // Bind to all interfaces, restrict via network policies
}

fn default_internal_port() -> u16 {
    9090 // Internal server-to-server port
}

fn default_worker_threads() -> usize {
    num_cpus::get()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_backend")]
    pub backend: String,

    pub connection_string: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { backend: default_backend(), connection_string: None }
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

    #[serde(default = "default_cache_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            max_capacity: default_cache_max_capacity(),
            ttl_seconds: default_cache_ttl_seconds(),
        }
    }
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_max_capacity() -> u64 {
    10_000
}

fn default_cache_ttl_seconds() -> u64 {
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

    /// Accepted signature algorithms
    #[serde(default = "default_accepted_algorithms")]
    pub accepted_algorithms: Vec<String>,

    /// Enforce audience validation
    #[serde(default = "default_enforce_audience")]
    pub enforce_audience: bool,

    /// Expected audience value
    #[serde(default = "default_audience")]
    pub audience: String,

    /// Enforce scope validation
    #[serde(default = "default_enforce_scopes")]
    pub enforce_scopes: bool,

    /// Enable replay protection (requires Redis)
    #[serde(default = "default_replay_protection")]
    pub replay_protection: bool,

    /// Control Plane JWKS base URL
    #[serde(default = "default_jwks_base_url")]
    pub jwks_base_url: String,

    /// OAuth introspection endpoint (optional)
    pub oauth_introspection_endpoint: Option<String>,

    /// OAuth introspection client ID for authentication (optional)
    pub oauth_introspection_client_id: Option<String>,

    /// OAuth introspection client secret for authentication (optional)
    pub oauth_introspection_client_secret: Option<String>,

    /// OIDC discovery cache TTL in seconds
    #[serde(default = "default_oidc_discovery_cache_ttl")]
    pub oidc_discovery_cache_ttl: u64,

    /// OAuth introspection result cache TTL in seconds
    #[serde(default = "default_introspection_cache_ttl")]
    pub introspection_cache_ttl: u64,

    /// Internal JWKS file path (optional)
    pub internal_jwks_path: Option<PathBuf>,

    /// Internal JWKS environment variable name (optional)
    pub internal_jwks_env: Option<String>,

    /// Internal JWT issuer
    #[serde(default = "default_internal_issuer")]
    pub internal_issuer: String,

    /// Internal JWT audience
    #[serde(default = "default_internal_audience")]
    pub internal_audience: String,

    /// Redis URL for replay protection (optional)
    pub redis_url: Option<String>,

    /// Clock skew tolerance in seconds (for timestamp validation)
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: Option<u64>,

    /// Maximum token age in seconds (from iat to now)
    #[serde(default = "default_max_token_age_seconds")]
    pub max_token_age_seconds: Option<u64>,

    /// Issuer allowlist (if set, only these issuers are accepted)
    pub issuer_allowlist: Option<Vec<String>>,

    /// Issuer blocklist (these issuers are always rejected)
    pub issuer_blocklist: Option<Vec<String>>,

    /// Allowed audience values (for audience validation)
    #[serde(default = "default_allowed_audiences")]
    pub allowed_audiences: Vec<String>,

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

    /// OAuth introspection URL
    pub introspection_url: Option<String>,

    /// Required scopes for authorization
    #[serde(default = "default_required_scopes")]
    pub required_scopes: Vec<String>,

    /// JWKS URL (alternative to jwks_base_url)
    #[serde(default = "default_jwks_url")]
    pub jwks_url: String,

    /// Management API base URL for token validation
    #[serde(default = "default_management_api_url")]
    pub management_api_url: String,

    /// Timeout for management API calls in milliseconds
    #[serde(default = "default_management_api_timeout")]
    pub management_api_timeout_ms: u64,

    /// Cache TTL for management API responses (org/vault) in seconds
    #[serde(default = "default_management_cache_ttl")]
    pub management_cache_ttl_seconds: u64,

    /// Cache TTL for client certificates in seconds
    #[serde(default = "default_cert_cache_ttl")]
    pub cert_cache_ttl_seconds: u64,

    /// Whether to verify vault ownership against management API
    #[serde(default = "default_true")]
    pub management_verify_vault_ownership: bool,

    /// Whether to verify organization status against management API
    #[serde(default = "default_true")]
    pub management_verify_org_status: bool,

    /// Server identity Ed25519 private key (PEM format) for signing server-to-management requests
    /// This key is used to authenticate the server when making calls to the management API
    /// If not provided, will be generated on startup and logged (not recommended for production)
    pub server_identity_private_key: Option<String>,

    /// Server identity key ID (kid) for JWKS
    /// Used to identify the server's public key in its JWKS endpoint
    #[serde(default = "default_server_identity_kid")]
    pub server_identity_kid: String,

    /// Server ID for JWT subject claim (sub: "server:{server_id}")
    #[serde(default = "default_server_id")]
    pub server_id: String,

    /// Service discovery configuration for management API
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode (none or kubernetes)
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_discovery_cache_ttl")]
    pub cache_ttl_seconds: u64,

    /// Whether to enable health checking of endpoints
    #[serde(default = "default_discovery_health_check")]
    pub enable_health_check: bool,

    /// Health check interval (in seconds)
    #[serde(default = "default_discovery_health_check_interval")]
    pub health_check_interval_seconds: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl_seconds: default_discovery_cache_ttl(),
            enable_health_check: default_discovery_health_check(),
            health_check_interval_seconds: default_discovery_health_check_interval(),
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

fn default_jwks_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_accepted_algorithms() -> Vec<String> {
    vec!["EdDSA".to_string(), "RS256".to_string()]
}

fn default_enforce_audience() -> bool {
    true
}

fn default_audience() -> String {
    "https://api.inferadb.com/evaluate".to_string()
}

fn default_enforce_scopes() -> bool {
    true
}

fn default_clock_skew_seconds() -> Option<u64> {
    Some(60) // 1 minute tolerance for clock differences
}

fn default_max_token_age_seconds() -> Option<u64> {
    Some(86400) // 24 hours maximum token age
}

fn default_allowed_audiences() -> Vec<String> {
    vec!["https://api.inferadb.com/evaluate".to_string()]
}

fn default_require_jti() -> bool {
    false // Optional by default, but required when replay_protection is enabled
}

fn default_oauth_enabled() -> bool {
    false
}

fn default_required_scopes() -> Vec<String> {
    vec![]
}

fn default_jwks_url() -> String {
    String::new()
}

fn default_replay_protection() -> bool {
    false
}

fn default_jwks_base_url() -> String {
    "https://auth.inferadb.com/.well-known".to_string()
}

fn default_oidc_discovery_cache_ttl() -> u64 {
    86400 // 24 hours in seconds
}

fn default_introspection_cache_ttl() -> u64 {
    60 // 1 minute in seconds
}

fn default_internal_issuer() -> String {
    "https://internal.inferadb.com".to_string()
}

fn default_internal_audience() -> String {
    "https://api.inferadb.com/internal".to_string()
}

fn default_management_api_url() -> String {
    // Management API internal server port (server-to-server communication)
    // This should point to the Management API's internal_port (default 9091)
    // NOT the public http_port (default 3000)
    "http://localhost:9091".to_string()
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

fn default_server_identity_kid() -> String {
    "server-default".to_string()
}

fn default_server_id() -> String {
    "default".to_string()
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

/// Multi-tenancy configuration
///
/// Controls default organization and vault used when authentication is disabled.
/// These values are auto-generated on first startup if not specified.
///
/// # Configuration
///
/// YAML:
/// ```yaml
/// multi_tenancy:
///   default_vault: "550e8400-e29b-41d4-a716-446655440000"
///   default_organization: "550e8400-e29b-41d4-a716-446655440001"
/// ```
///
/// Environment:
/// ```bash
/// INFERA__MULTI_TENANCY__DEFAULT_VAULT=550e8400-e29b-41d4-a716-446655440000
/// INFERA__MULTI_TENANCY__DEFAULT_ORGANIZATION=550e8400-e29b-41d4-a716-446655440001
/// ```
///
/// # Auto-Initialization
///
/// On first startup, if these values are not set:
/// 1. A new Organization is created with name "Default Organization"
/// 2. A new Vault is created with name "Default Vault"
/// 3. The SystemConfig is stored in the database
/// 4. All subsequent startups use these defaults
///
/// If values are specified in configuration:
/// - The system will use those UUIDs
/// - Organizations and Vaults will be created if they don't exist
/// - Existing organizations/vaults with those IDs will be reused
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiTenancyConfig {
    /// Default vault UUID (auto-generated on first startup if not set)
    #[serde(default)]
    pub default_vault: Option<String>,

    /// Default organization UUID (auto-generated on first startup if not set)
    #[serde(default)]
    pub default_organization: Option<String>,
}

impl Config {
    /// Validate configuration at startup
    ///
    /// This method performs comprehensive validation of all configuration values,
    /// catching errors early before they cause runtime failures.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate server config
        if self.server.port == 0 {
            anyhow::bail!("server.port cannot be 0");
        }
        if self.server.worker_threads == 0 {
            anyhow::bail!("server.worker_threads must be greater than 0");
        }

        // Validate store backend
        if self.store.backend != "memory" && self.store.backend != "foundationdb" {
            anyhow::bail!(
                "Invalid store.backend: '{}'. Must be 'memory' or 'foundationdb'",
                self.store.backend
            );
        }

        // Validate FoundationDB configuration
        if self.store.backend == "foundationdb" && self.store.connection_string.is_none() {
            anyhow::bail!("store.connection_string is required when using FoundationDB backend");
        }

        // Validate authentication config (delegates to AuthConfig::validate)
        self.auth.validate().map_err(|e| anyhow::anyhow!(e))?;

        // Additional validation for management API URL format
        if !self.auth.management_api_url.starts_with("http://")
            && !self.auth.management_api_url.starts_with("https://")
        {
            anyhow::bail!(
                "auth.management_api_url must start with http:// or https://, got: {}",
                self.auth.management_api_url
            );
        }
        if self.auth.management_api_url.ends_with('/') {
            anyhow::bail!(
                "auth.management_api_url must not end with trailing slash: {}",
                self.auth.management_api_url
            );
        }

        // Validate JWKS base URL format
        if !self.auth.jwks_base_url.starts_with("http://")
            && !self.auth.jwks_base_url.starts_with("https://")
        {
            anyhow::bail!(
                "auth.jwks_base_url must start with http:// or https://, got: {}",
                self.auth.jwks_base_url
            );
        }
        if self.auth.jwks_base_url.ends_with('/') {
            anyhow::bail!(
                "auth.jwks_base_url must not end with trailing slash: {}",
                self.auth.jwks_base_url
            );
        }

        // Validate server identity configuration
        if self.auth.server_identity_kid.is_empty() {
            anyhow::bail!("auth.server_identity_kid cannot be empty");
        }
        if self.auth.server_id.is_empty() {
            anyhow::bail!("auth.server_id cannot be empty");
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
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwks_cache_ttl: default_jwks_cache_ttl(),
            accepted_algorithms: default_accepted_algorithms(),
            enforce_audience: default_enforce_audience(),
            audience: default_audience(),
            enforce_scopes: default_enforce_scopes(),
            replay_protection: default_replay_protection(),
            jwks_base_url: default_jwks_base_url(),
            oauth_introspection_endpoint: None,
            oauth_introspection_client_id: None,
            oauth_introspection_client_secret: None,
            oidc_discovery_cache_ttl: default_oidc_discovery_cache_ttl(),
            introspection_cache_ttl: default_introspection_cache_ttl(),
            internal_jwks_path: None,
            internal_jwks_env: Some("INFERADB_INTERNAL_JWKS".to_string()),
            internal_issuer: default_internal_issuer(),
            internal_audience: default_internal_audience(),
            redis_url: None,
            clock_skew_seconds: default_clock_skew_seconds(),
            max_token_age_seconds: default_max_token_age_seconds(),
            issuer_allowlist: None,
            issuer_blocklist: None,
            allowed_audiences: default_allowed_audiences(),
            require_jti: default_require_jti(),
            oauth_enabled: default_oauth_enabled(),
            oidc_discovery_url: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            introspection_url: None,
            required_scopes: default_required_scopes(),
            jwks_url: default_jwks_url(),
            management_api_url: default_management_api_url(),
            management_api_timeout_ms: default_management_api_timeout(),
            management_cache_ttl_seconds: default_management_cache_ttl(),
            cert_cache_ttl_seconds: default_cert_cache_ttl(),
            management_verify_vault_ownership: default_true(),
            management_verify_org_status: default_true(),
            server_identity_private_key: None,
            server_identity_kid: default_server_identity_kid(),
            server_id: default_server_id(),
            discovery: DiscoveryConfig::default(),
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
        // Warn if JWKS base URL is missing
        if self.jwks_base_url.is_empty() && self.jwks_url.is_empty() {
            tracing::warn!(
                "jwks_base_url and jwks_url are empty. \
                 Tenant JWT authentication will not work."
            );
        }

        // Warn if internal JWT sources are configured but both are missing
        let has_internal_path = self.internal_jwks_path.is_some();
        let has_internal_env = self.internal_jwks_env.is_some();

        if !has_internal_path && !has_internal_env {
            tracing::info!(
                "No internal JWT JWKS source configured. \
                 Internal service-to-service authentication will not be available. \
                 Set internal_jwks_path or internal_jwks_env to enable."
            );
        }

        // CRITICAL: Reject if accepted_algorithms is empty
        if self.accepted_algorithms.is_empty() {
            return Err(
                "accepted_algorithms cannot be empty. At least one algorithm must be configured."
                    .to_string(),
            );
        }

        // CRITICAL: Reject if accepted_algorithms contains forbidden algorithms
        const FORBIDDEN: &[&str] = &["none", "HS256", "HS384", "HS512"];
        for alg in &self.accepted_algorithms {
            if FORBIDDEN.contains(&alg.as_str()) {
                return Err(format!(
                    "Algorithm '{}' is forbidden for security reasons (symmetric or none). \
                     Only asymmetric algorithms (EdDSA, RS256, ES256, etc.) are allowed.",
                    alg
                ));
            }
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

        // Warn if audience validation is disabled
        if !self.enforce_audience {
            tracing::warn!(
                "Audience validation is disabled. This is a security risk. \
                 Tokens intended for other services may be accepted. \
                 Set enforce_audience=true for production."
            );
        }

        // Warn if allowed_audiences is empty but enforce_audience is true
        if self.enforce_audience && self.allowed_audiences.is_empty() {
            tracing::warn!(
                "Audience enforcement is enabled but allowed_audiences is empty. \
                 All tokens will be rejected due to audience mismatch."
            );
        }

        // Info about issuer validation
        if self.issuer_allowlist.is_some() {
            tracing::info!(
                "Issuer allowlist is configured. Only tokens from allowed issuers will be accepted."
            );
        }

        if self.issuer_blocklist.is_some() {
            tracing::info!(
                "Issuer blocklist is configured. Tokens from blocked issuers will be rejected."
            );
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: default_host(),
                port: default_port(),
                internal_host: default_internal_host(),
                internal_port: default_internal_port(),
                worker_threads: default_worker_threads(),
            },
            store: StoreConfig { backend: default_backend(), connection_string: None },
            cache: CacheConfig {
                enabled: default_cache_enabled(),
                max_capacity: default_cache_max_capacity(),
                ttl_seconds: default_cache_ttl_seconds(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                metrics_enabled: default_metrics_enabled(),
                tracing_enabled: default_tracing_enabled(),
            },
            auth: AuthConfig::default(),
            multi_tenancy: MultiTenancyConfig::default(),
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
        builder.add_source(Environment::with_prefix("INFERA").separator("__").try_parsing(true));

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
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.host, "0.0.0.0");
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_auth_config_validation_without_jwks_url() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let config = AuthConfig { jwks_base_url: String::new(), ..Default::default() };

        // Should warn but not panic
        let _ = config.validate();
    }

    #[test]
    fn test_auth_config_validation_no_internal_jwks_source() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        let config =
            AuthConfig { internal_jwks_path: None, internal_jwks_env: None, ..Default::default() };

        // Should log info but not panic
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
    fn test_auth_config_validation_no_accepted_algorithms() {
        let _subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let config = AuthConfig { accepted_algorithms: vec![], ..Default::default() };

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
            jwks_base_url: "https://auth.example.com".to_string(),
            internal_jwks_env: Some("JWKS_ENV".to_string()),
            replay_protection: false,
            accepted_algorithms: vec!["EdDSA".to_string()],
            ..Default::default()
        };

        // Should not log any warnings
        let _ = config.validate();
    }
}
