//! # InferaDB Server Binary
//!
//! Main entrypoint for the InferaDB policy decision engine server.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use infera_auth::jwks_cache::JwksCache;
use infera_bin::initialization;
use infera_config::load_or_default;
use infera_core::{Evaluator, ipl::Schema};
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

    // Validate authentication configuration
    if let Err(e) = config.auth.validate() {
        eprintln!("Configuration validation error: {}", e);
        std::process::exit(1);
    }

    let config = Arc::new(config);

    // Initialize storage backend
    // TODO: Support multiple backends based on config
    let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
    tracing::info!("Using in-memory storage backend");

    // Initialize system (create default account/vault if needed)
    let system_config = initialization::initialize_system(&store, &config).await?;
    tracing::info!(
        "Using default vault {} for account {}",
        system_config.default_vault,
        system_config.default_account
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

    // Create evaluator
    let evaluator = Arc::new(Evaluator::new(
        Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>,
        schema,
        wasm_host,
        system_config.default_vault,
    ));
    tracing::info!("Policy evaluator initialized");

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
        );

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

    // Start API server
    tracing::info!("Starting API server on {}:{}", config.server.host, config.server.port);

    infera_api::serve(
        evaluator,
        store,
        config,
        jwks_cache,
        system_config.default_vault,
        system_config.default_account,
    )
    .await?;

    Ok(())
}
