//! # InferaDB Engine Binary
//!
//! Main entrypoint for the InferaDB authorization engine (Policy Decision Point).

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_engine_auth::jwks_cache::JwksCache;
use inferadb_engine_config::load_or_default;
use inferadb_engine_core::ipl::Schema;
use inferadb_engine_store::StorageFactory;
use inferadb_engine_wasm::WasmHost;

#[derive(Parser, Debug)]
#[command(name = "inferadb-engine")]
#[command(about = "InferaDB Authorization Engine", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// HTTP address (overrides config), e.g., "0.0.0.0:8080"
    #[arg(long)]
    http: Option<String>,

    /// Environment (development, staging, production)
    #[arg(short, long, env = "ENVIRONMENT", default_value = "development")]
    environment: String,
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
    inferadb_engine_observe::init()?;

    // Load configuration
    let mut config = load_or_default(&args.config);

    // Override with CLI args
    if let Some(ref addr) = args.http {
        config.listen.http = addr.clone();
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
    use inferadb_engine_config::DiscoveryMode;
    use inferadb_engine_observe::startup::{
        ConfigEntry, ServiceInfo, StartupDisplay, private_key_hint,
    };

    // Create the private key entry based on whether it's configured
    let private_key_entry = if let Some(ref pem) = config.pem {
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

    // Create mesh service entry with discovery context
    let mesh_url = config.effective_mesh_url();
    let mesh_entry = if config.is_discovery_enabled() {
        ConfigEntry::new(
            "Network",
            "Control Endpoint",
            format!("{} ({})", mesh_url, discovery_mode_text),
        )
    } else {
        ConfigEntry::new("Network", "Control Endpoint", format!("{} (local)", mesh_url))
    };

    StartupDisplay::new(ServiceInfo {
        name: "InferaDB Engine",
        subtext: "Authorization Engine",
        version: env!("CARGO_PKG_VERSION"),
        environment: args.environment.clone(),
    })
    .entries(vec![
        // General
        ConfigEntry::new("General", "Environment", &args.environment),
        ConfigEntry::new("General", "Configuration File", &config_path),
        // Storage
        ConfigEntry::new("Storage", "Backend", &config.storage),
        // Listen
        ConfigEntry::new("Listen", "HTTP", &config.listen.http),
        ConfigEntry::new("Listen", "gRPC", &config.listen.grpc),
        ConfigEntry::new("Listen", "Mesh", &config.listen.mesh),
        ConfigEntry::separator("Listen"),
        mesh_entry,
        discovery_entry,
        private_key_entry,
    ])
    .display();

    let config = Arc::new(config);

    // Initialize components
    use inferadb_engine_observe::startup::{log_initialized, log_ready, log_skipped};

    // Initialize storage backend based on configuration
    let store: Arc<dyn inferadb_engine_store::InferaStore> =
        StorageFactory::from_str(&config.storage, config.foundationdb.cluster_file.clone())
            .await
            .map_err(|e| {
            anyhow::anyhow!("Failed to initialize storage backend '{}': {}", config.storage, e)
        })?;
    log_initialized(&format!("Storage ({})", config.storage));

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
            .time_to_live(Duration::from_secs(config.token.cache_ttl))
            .time_to_idle(Duration::from_secs(config.token.cache_ttl * 2))
            .build(),
    );

    // Create the JWKS cache
    let jwks_cache = JwksCache::new(
        config.mesh.url.clone(),
        cache,
        Duration::from_secs(config.token.cache_ttl),
    )?;
    log_initialized("JWKS cache");

    let jwks_cache = Some(Arc::new(jwks_cache));

    // Initialize server identity for server-to-control authentication
    let server_identity = if !config.effective_mesh_url().is_empty() {
        use inferadb_engine_control_client::ServerIdentity;

        let identity = if let Some(ref pem) = config.pem {
            ServerIdentity::from_pem(pem)
                .map_err(|e| anyhow::anyhow!("Failed to load server identity from PEM: {}", e))?
        } else {
            // Generate new identity and display in formatted box
            let identity = ServerIdentity::generate();
            let pem = identity.to_pem();
            inferadb_engine_observe::startup::print_generated_keypair(&pem, "pem");
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
        log_skipped("Identity", "mesh.url not configured");
        None
    };

    // Initialize replication components if enabled
    let change_publisher: Option<Arc<dyn inferadb_engine_types::ChangePublisher>> =
        if config.replication.enabled {
            use inferadb_engine_repl::{ChangeFeed, ChangeFeedConfig, ConflictResolutionStrategy};

            // Convert config to change feed configuration using agent buffer_size
            let feed_config =
                ChangeFeedConfig { channel_capacity: config.replication.agent.buffer_size };

            let change_feed = Arc::new(ChangeFeed::with_config(feed_config));

            // Convert conflict resolution strategy from config to repl crate type
            let conflict_strategy = match config.replication.conflict_resolution {
                inferadb_engine_config::ConflictResolutionConfig::LastWriteWins => {
                    ConflictResolutionStrategy::LastWriteWins
                },
                inferadb_engine_config::ConflictResolutionConfig::SourcePriority => {
                    ConflictResolutionStrategy::SourcePriority
                },
                inferadb_engine_config::ConflictResolutionConfig::InsertWins => {
                    ConflictResolutionStrategy::InsertWins
                },
            };

            log_initialized(&format!(
                "Replication ({:?}, local_region={}, conflict_resolution={:?})",
                config.replication.strategy, config.replication.local_region, conflict_strategy
            ));

            // Log agent configuration at debug level
            tracing::debug!(
                max_retries = config.replication.agent.max_retries,
                retry_delay_ms = config.replication.agent.retry_delay_ms,
                batch_size = config.replication.agent.batch_size,
                request_timeout_secs = config.replication.agent.request_timeout_secs,
                buffer_size = config.replication.agent.buffer_size,
                "Replication agent configuration"
            );

            // TODO: When topology configuration (replication.regions and
            // replication.replication_targets) is implemented, create and start the
            // full ReplicationAgent here:
            //
            // 1. Build Topology from config.replication.regions
            // 2. Create ConflictResolver with conflict_strategy and region priorities
            // 3. Convert agent config to repl crate ReplicationConfig:
            //    - max_retries: config.replication.agent.max_retries
            //    - retry_delay: Duration::from_millis(config.replication.agent.retry_delay_ms)
            //    - batch_size: config.replication.agent.batch_size
            //    - request_timeout:
            //      Duration::from_secs(config.replication.agent.request_timeout_secs)
            //    - buffer_size: config.replication.agent.buffer_size
            // 4. Create ReplicationAgent::new(topology, change_feed, store, resolver, agent_config)
            // 5. Call agent.start().await

            Some(change_feed)
        } else {
            log_skipped("Replication", "disabled in config");
            None
        };

    // Clone components for each server
    let public_components = inferadb_engine_api::ServerComponents {
        store: Arc::clone(&store),
        schema: Arc::clone(&schema),
        wasm_host: wasm_host.clone(),
        config: Arc::clone(&config),
        jwks_cache: jwks_cache.clone(),
        server_identity: server_identity.clone(),
        change_publisher: change_publisher.clone(),
    };

    let internal_components = inferadb_engine_api::ServerComponents {
        store: Arc::clone(&store),
        schema: Arc::clone(&schema),
        wasm_host: wasm_host.clone(),
        config: Arc::clone(&config),
        jwks_cache: jwks_cache.clone(),
        server_identity: server_identity.clone(),
        change_publisher: change_publisher.clone(),
    };

    // Bind listeners (addresses are already validated at config.validate())
    let public_listener = tokio::net::TcpListener::bind(&config.listen.http).await?;
    let internal_listener = tokio::net::TcpListener::bind(&config.listen.mesh).await?;

    // Log ready status
    log_ready("Authorization Engine");

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(2);
    let mut shutdown_rx_internal = shutdown_tx.subscribe();

    // Spawn task to handle shutdown signals
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });
    tokio::try_join!(
        inferadb_engine_api::serve_public(public_components, public_listener, async move {
            shutdown_rx.recv().await.ok();
        }),
        inferadb_engine_api::serve_internal(internal_components, internal_listener, async move {
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
