//! # InferaDB Server Binary
//!
//! Main entrypoint for the InferaDB policy decision engine server.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_auth::jwks_cache::JwksCache;
use inferadb_bin::initialization;
use inferadb_config::load_or_default;
use inferadb_core::ipl::Schema;
use inferadb_store::MemoryBackend;
use inferadb_wasm::WasmHost;

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
    // Initialize Rustls crypto provider (must be done before any TLS operations)
    // We use aws-lc-rs for FIPS compliance and better performance
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install default crypto provider"))?;

    // Parse command-line arguments
    let args = Args::parse();

    // Initialize observability
    inferadb_observe::init()?;

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

    // Display startup banner and configuration summary
    use inferadb_observe::startup::{ConfigEntry, ServiceInfo, StartupDisplay};
    StartupDisplay::new(ServiceInfo {
        name: "InferaDB",
        subtext: "Policy Decision Engine Server",
        version: env!("CARGO_PKG_VERSION"),
        environment: "development".to_string(), // TODO: Get from config
    })
    .entries(vec![
        ConfigEntry::new("General", "config_file", &args.config),
        ConfigEntry::new("Server", "public_host", &config.server.host),
        ConfigEntry::new("Server", "public_port", config.server.port),
        ConfigEntry::new("Server", "internal_host", &config.server.internal_host),
        ConfigEntry::new("Server", "internal_port", config.server.internal_port),
        ConfigEntry::new("Auth", "jwks_base_url", &config.auth.jwks_base_url),
        ConfigEntry::new("Auth", "jwks_cache_ttl", format!("{}s", config.auth.jwks_cache_ttl)),
    ])
    .display();

    let config = Arc::new(config);

    // ━━━ Initialize Components ━━━
    use inferadb_observe::startup::{log_initialized, log_phase, log_ready, log_skipped};
    log_phase("Initializing Components");

    // Initialize storage backend
    // TODO: Support multiple backends based on config
    let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
    log_initialized("Storage (memory)");

    // Initialize system (create default organization/vault if needed)
    let system_config = initialization::initialize_system(&store, &config).await?;
    log_initialized(&format!(
        "System (org: {}, vault: {})",
        system_config.default_organization, system_config.default_vault
    ));

    // Initialize WASM host
    let wasm_host = WasmHost::new().ok().map(Arc::new);
    if wasm_host.is_some() {
        log_initialized("WASM host");
    } else {
        log_skipped("WASM host", "initialization failed");
    }

    // Create empty schema (TODO: Load from config)
    let schema = Arc::new(Schema::new(vec![]));
    log_initialized("Schema");

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
    log_initialized("JWKS cache");

    let jwks_cache = Some(Arc::new(jwks_cache));

    // Initialize server identity for server-to-management authentication
    let server_identity = if !config.auth.management_api_url.is_empty() {
        use inferadb_auth::ServerIdentity;

        let identity = if let Some(ref pem) = config.auth.server_identity_private_key {
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

        log_initialized("Server identity");
        Some(Arc::new(identity))
    } else {
        log_skipped("Server identity", "management_api_url not configured");
        None
    };

    // ━━━ Start Server ━━━
    log_phase("Starting Server");

    // Clone components for each server
    let public_components = inferadb_api::ServerComponents {
        store: Arc::clone(&store),
        schema: Arc::clone(&schema),
        wasm_host: wasm_host.clone(),
        config: Arc::clone(&config),
        jwks_cache: jwks_cache.clone(),
        default_vault: system_config.default_vault,
        default_organization: system_config.default_organization,
        server_identity: server_identity.clone(),
    };

    let internal_components = inferadb_api::ServerComponents {
        store: Arc::clone(&store),
        schema: Arc::clone(&schema),
        wasm_host: wasm_host.clone(),
        config: Arc::clone(&config),
        jwks_cache: jwks_cache.clone(),
        default_vault: system_config.default_vault,
        default_organization: system_config.default_organization,
        server_identity: server_identity.clone(),
    };

    // Bind listeners
    let public_addr = format!("{}:{}", config.server.host, config.server.port);
    let internal_addr = format!("{}:{}", config.server.internal_host, config.server.internal_port);

    let public_listener = tokio::net::TcpListener::bind(&public_addr).await?;
    let internal_listener = tokio::net::TcpListener::bind(&internal_addr).await?;

    // Log ready status
    log_ready("InferaDB", &[("Public API", &public_addr), ("Internal API", &internal_addr)]);

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(2);
    let mut shutdown_rx_internal = shutdown_tx.subscribe();

    // Spawn task to handle shutdown signals
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });
    tokio::try_join!(
        inferadb_api::serve_public(public_components, public_listener, async move {
            shutdown_rx.recv().await.ok();
        }),
        inferadb_api::serve_internal(internal_components, internal_listener, async move {
            shutdown_rx_internal.recv().await.ok();
        })
    )?;

    Ok(())
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
    }

    tracing::info!("Shutdown signal received, draining connections...");
}
