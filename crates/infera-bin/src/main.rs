//! # InferaDB Server Binary
//!
//! Main entrypoint for the InferaDB policy decision engine server.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use infera_auth::jwks_cache::JwksCache;
use infera_bin::initialization;
use infera_config::load_or_default;
use infera_core::ipl::Schema;
use infera_store::MemoryBackend;
use infera_wasm::WasmHost;

#[derive(Parser, Debug)]
#[command(name = "inferadb")]
#[command(about = "InferaDB Policy Decision Engine", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Server port (overrides config)
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize observability
    infera_observe::init()?;

    tracing::info!("Starting InferaDB Policy Decision Engine");

    // Load configuration
    let mut config = load_or_default(&args.config);

    // Override with CLI args
    if let Some(port) = args.port {
        config.server.port = port;
    }

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Configuration validation error: {}", e);
        std::process::exit(1);
    }

    let config = Arc::new(config);

    // Initialize storage backend
    // TODO: Support multiple backends based on config
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    tracing::info!("Using in-memory storage backend");

    // Initialize system (create default organization/vault if needed)
    let system_config = initialization::initialize_system(&store, &config).await?;
    tracing::info!(
        "Using default vault {} for organization {}",
        system_config.default_vault,
        system_config.default_organization
    );

    // Initialize WASM host
    let wasm_host = WasmHost::new().ok().map(Arc::new);
    if wasm_host.is_some() {
        tracing::info!("WASM host initialized");
    } else {
        tracing::warn!("Failed to initialize WASM host");
    }

    // Create empty schema (TODO: Load from config)
    let schema = Arc::new(Schema::new(vec![]));
    tracing::info!("Schema loaded");

    // Initialize JWKS cache if authentication is enabled
    let jwks_cache = if config.auth.enabled {
        tracing::info!("Authentication ENABLED - initializing JWKS cache");

        // Create the moka cache with TTL and stale-while-revalidate support
        use std::time::Duration;
        let cache = Arc::new(
            moka::future::Cache::builder()
                .max_capacity(1000) // Up to 1000 tenants
                .time_to_live(Duration::from_secs(config.auth.jwks_cache_ttl))
                .time_to_idle(Duration::from_secs(config.auth.jwks_cache_ttl * 2))
                .build(),
        );

        // Create the JWKS cache
        let jwks_cache = JwksCache::new(
            config.auth.jwks_base_url.clone(),
            cache,
            Duration::from_secs(config.auth.jwks_cache_ttl),
        )?;

        tracing::info!(
            "JWKS cache initialized with TTL: {}s, base URL: {}",
            config.auth.jwks_cache_ttl,
            config.auth.jwks_base_url
        );

        Some(Arc::new(jwks_cache))
    } else {
        tracing::warn!("Authentication DISABLED - API endpoints will not require authentication");
        tracing::warn!("This mode should ONLY be used in development/testing environments");
        None
    };

    // Initialize server identity for server-to-management authentication
    let server_identity = if config.auth.enabled && !config.auth.management_api_url.is_empty() {
        use infera_auth::ServerIdentity;

        let identity = if let Some(ref pem) = config.auth.server_identity_private_key {
            // Load from configured PEM
            tracing::info!("Loading server identity from configuration");
            ServerIdentity::from_pem(
                config.auth.server_id.clone(),
                config.auth.server_identity_kid.clone(),
                pem,
            )
            .map_err(|e| anyhow::anyhow!("Failed to load server identity from PEM: {}", e))?
        } else {
            // Generate new identity and log the PEM (for development)
            tracing::warn!("No server identity configured - generating new Ed25519 keypair");
            tracing::warn!("This should ONLY be used in development environments");
            let identity = ServerIdentity::generate(
                config.auth.server_id.clone(),
                config.auth.server_identity_kid.clone(),
            );
            let pem = identity.to_pem();
            tracing::warn!(
                "Generated server identity PEM (save this to config for production):\n{}",
                pem
            );
            identity
        };

        tracing::info!(
            "Server identity initialized: server_id={}, kid={}",
            identity.server_id,
            identity.kid
        );

        Some(Arc::new(identity))
    } else {
        None
    };

    // Start API server
    tracing::info!("Starting API server on {}:{}", config.server.host, config.server.port);

    let components = infera_api::ServerComponents {
        store,
        schema,
        wasm_host,
        config,
        jwks_cache,
        default_vault: system_config.default_vault,
        default_organization: system_config.default_organization,
        server_identity,
    };

    infera_api::serve(components).await?;

    Ok(())
}
