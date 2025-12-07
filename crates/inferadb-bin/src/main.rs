//! # InferaDB Server Binary
//!
//! Main entrypoint for the InferaDB policy service.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_auth::jwks_cache::JwksCache;
use inferadb_config::load_or_default;
use inferadb_core::ipl::Schema;
use inferadb_store::MemoryBackend;
use inferadb_wasm::WasmHost;

#[derive(Parser, Debug)]
#[command(name = "inferadb")]
#[command(about = "InferaDB Policy Service", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Public REST address (overrides config), e.g., "0.0.0.0:8080"
    #[arg(long)]
    public_rest: Option<String>,

    /// Environment (development, staging, production)
    #[arg(short, long, env = "ENVIRONMENT", default_value = "development")]
    environment: String,

    /// Worker ID for distributed deployments (0-1023)
    #[arg(short, long, env = "WORKER_ID", default_value = "0")]
    worker_id: u16,
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

    // Clear terminal in development mode when running interactively
    if args.environment != "production" && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        print!("\x1B[2J\x1B[1;1H");
    }

    // Initialize observability
    inferadb_observe::init()?;

    // Load configuration
    let mut config = load_or_default(&args.config);

    // Override with CLI args
    if let Some(ref addr) = args.public_rest {
        config.server.public_rest = addr.clone();
    }

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Configuration validation error: {}", e);
        std::process::exit(1);
    }

    // Get full path of configuration file
    let config_path = std::fs::canonicalize(&args.config)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| args.config.clone());

    // Display startup banner and configuration summary
    use inferadb_config::DiscoveryMode;
    use inferadb_observe::startup::{ConfigEntry, ServiceInfo, StartupDisplay, private_key_hint};

    // Create the private key entry based on whether it's configured
    let private_key_entry = if let Some(ref pem) = config.identity.private_key_pem {
        ConfigEntry::new("Identity", "Private Key", private_key_hint(pem))
    } else {
        ConfigEntry::warning("Identity", "Private Key", "○ Unassigned")
    };

    // Create discovery mode entry with descriptive text
    let (discovery_entry, discovery_mode_text) = match &config.discovery.mode {
        DiscoveryMode::None => {
            (ConfigEntry::warning("Network", "Service Discovery", "○ Disabled"), "local")
        },
        DiscoveryMode::Kubernetes => {
            (ConfigEntry::new("Network", "Service Discovery", "Kubernetes"), "kubernetes")
        },
        DiscoveryMode::Tailscale { local_cluster, .. } => (
            ConfigEntry::new(
                "Network",
                "Service Discovery",
                format!("Tailscale ({})", local_cluster),
            ),
            "tailscale",
        ),
    };

    // Create management service entry with discovery context
    let mgmt_url = config.effective_management_url();
    let mgmt_entry = if config.is_discovery_enabled() {
        ConfigEntry::new(
            "Network",
            "Management Service",
            format!("{} ({})", mgmt_url, discovery_mode_text),
        )
    } else {
        ConfigEntry::new("Network", "Management Service", format!("{} (local)", mgmt_url))
    };

    StartupDisplay::new(ServiceInfo {
        name: "InferaDB",
        subtext: "Policy Service",
        version: env!("CARGO_PKG_VERSION"),
        environment: args.environment.clone(),
    })
    .entries(vec![
        // General
        ConfigEntry::new("General", "Environment", &args.environment),
        ConfigEntry::new("General", "Worker ID", args.worker_id),
        ConfigEntry::new("General", "Configuration File", &config_path),
        // Storage
        ConfigEntry::new("Storage", "Backend", &config.storage.backend),
        // Network
        ConfigEntry::new("Network", "Public API (REST)", &config.server.public_rest),
        ConfigEntry::new("Network", "Public API (gRPC)", &config.server.public_grpc),
        ConfigEntry::new("Network", "Private API (REST)", &config.server.private_rest),
        ConfigEntry::separator("Network"),
        mgmt_entry,
        discovery_entry,
        private_key_entry,
    ])
    .display();

    let config = Arc::new(config);

    // Initialize components
    use inferadb_observe::startup::{log_initialized, log_ready, log_skipped};

    // Initialize storage backend
    // TODO: Support multiple backends based on config
    let store: Arc<dyn inferadb_store::InferaStore> = Arc::new(MemoryBackend::new());
    log_initialized("Storage (memory)");

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
        config.auth.jwks_url.clone(),
        cache,
        Duration::from_secs(config.auth.jwks_cache_ttl),
    )?;
    log_initialized("JWKS cache");

    let jwks_cache = Some(Arc::new(jwks_cache));

    // Initialize server identity for server-to-management authentication
    let server_identity = if !config.effective_management_url().is_empty() {
        use inferadb_auth::ServerIdentity;

        let identity = if let Some(ref pem) = config.identity.private_key_pem {
            ServerIdentity::from_pem(pem)
                .map_err(|e| anyhow::anyhow!("Failed to load server identity from PEM: {}", e))?
        } else {
            // Generate new identity and display in formatted box
            let identity = ServerIdentity::generate();
            let pem = identity.to_pem();
            inferadb_observe::startup::print_generated_keypair(&pem, "identity.private_key_pem");
            identity
        };

        tracing::info!(
            server_id = %identity.server_id,
            kid = %identity.kid,
            "Server identity initialized"
        );

        log_initialized("Identity");
        Some(Arc::new(identity))
    } else {
        log_skipped("Identity", "management_service.service_url not configured");
        None
    };

    // Clone components for each server
    let public_components = inferadb_api::ServerComponents {
        store: Arc::clone(&store),
        schema: Arc::clone(&schema),
        wasm_host: wasm_host.clone(),
        config: Arc::clone(&config),
        jwks_cache: jwks_cache.clone(),
        server_identity: server_identity.clone(),
    };

    let internal_components = inferadb_api::ServerComponents {
        store: Arc::clone(&store),
        schema: Arc::clone(&schema),
        wasm_host: wasm_host.clone(),
        config: Arc::clone(&config),
        jwks_cache: jwks_cache.clone(),
        server_identity: server_identity.clone(),
    };

    // Bind listeners (addresses are already validated at config.validate())
    let public_listener = tokio::net::TcpListener::bind(&config.server.public_rest).await?;
    let internal_listener = tokio::net::TcpListener::bind(&config.server.private_rest).await?;

    // Log ready status
    log_ready("Policy Service");

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
