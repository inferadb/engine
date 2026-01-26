//! # InferaDB Engine Binary
//!
//! Main entrypoint for the InferaDB authorization engine (Policy Decision Point).

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use inferadb_engine_auth::SigningKeyCache;
use inferadb_engine_config::load_or_default;
use inferadb_engine_core::ipl::{Schema, parse_schema};
use inferadb_engine_repository::EngineStorage;
use inferadb_engine_wasm::WasmHost;
use inferadb_storage::MemoryBackend;
use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig};

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

    /// Force development mode with in-memory storage.
    /// Use this flag for local development and testing without Ledger.
    /// In production, Ledger storage is the default and required.
    #[arg(long)]
    dev_mode: bool,
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

    // Apply environment-aware defaults (in development, auto-fallback to memory if no Ledger
    // config)
    config.apply_environment_defaults(&args.environment);

    // Handle --dev-mode flag: force memory storage for development/testing
    if args.dev_mode {
        tracing::info!("Development mode enabled via --dev-mode flag: using memory storage");
        config.storage = "memory".to_string();
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
    use inferadb_engine_observe::startup::{
        ConfigEntry, ServiceInfo, StartupDisplay, private_key_hint,
    };

    // Create the private key entry based on whether it's configured
    let private_key_entry = if let Some(ref pem) = config.pem {
        ConfigEntry::new("Identity", "Private Key", private_key_hint(pem))
    } else {
        ConfigEntry::warning("Identity", "Private Key", "○ Unassigned")
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
        ConfigEntry::separator("Listen"),
        private_key_entry,
    ])
    .display();

    let config = Arc::new(config);

    // Initialize components
    use inferadb_engine_observe::startup::{log_initialized, log_ready, log_skipped};
    // Initialize storage backend based on configuration
    // Memory backend uses EngineStorage<MemoryBackend> from the repository pattern
    // Ledger uses EngineStorage<LedgerBackend> (production)
    //
    // We also create a PublicSigningKeyStore for the SigningKeyCache:
    // - Memory: MemorySigningKeyStore (shared with storage)
    // - Ledger: LedgerSigningKeyStore (uses same LedgerClient)
    use inferadb_storage::auth::{MemorySigningKeyStore, PublicSigningKeyStore};
    use inferadb_storage_ledger::auth::LedgerSigningKeyStore;

    let (store, signing_key_store): (
        Arc<dyn inferadb_engine_store::InferaStore>,
        Arc<dyn PublicSigningKeyStore>,
    ) = match config.storage.as_str() {
        "memory" => {
            let signing_key_store = Arc::new(MemorySigningKeyStore::new());
            (
                Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build()),
                signing_key_store,
            )
        },
        "ledger" => {
            let endpoint = config
                .ledger
                .endpoint
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Ledger endpoint is required"))?
                .clone();
            let client_id = config
                .ledger
                .client_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Ledger client_id is required"))?;
            let namespace_id = config
                .ledger
                .namespace_id
                .ok_or_else(|| anyhow::anyhow!("Ledger namespace_id is required"))?;
            let ledger_config = LedgerBackendConfig::builder()
                .endpoints(vec![endpoint])
                .client_id(client_id)
                .namespace_id(namespace_id)
                .maybe_vault_id(config.ledger.vault_id)
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build Ledger config: {}", e))?;
            let ledger_backend = LedgerBackend::new(ledger_config)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to connect to Ledger: {}", e))?;

            // Create signing key store using the same LedgerClient
            let signing_key_store =
                Arc::new(LedgerSigningKeyStore::new(ledger_backend.client_arc()));

            (Arc::new(EngineStorage::builder().backend(ledger_backend).build()), signing_key_store)
        },
        // Note: "foundationdb" and "fdb" are rejected by config.validate() with a helpful error
        // message directing users to migrate to the Ledger backend.
        _ => {
            // This should not be reachable if config.validate() passed, but we handle it anyway
            return Err(anyhow::anyhow!(
                "Unknown storage backend: '{}'. Valid options are 'memory' or 'ledger'.",
                config.storage
            ));
        },
    };
    log_initialized(&format!("Storage ({})", config.storage));

    // Initialize WASM host
    let wasm_host = WasmHost::new().ok().map(Arc::new);
    if wasm_host.is_some() {
        log_initialized("WASM host");
    } else {
        log_skipped("WASM host", "initialization failed");
    }

    // Load schema from config if provided
    let schema = if let Some(schema_path) = &config.schema {
        let schema_content = std::fs::read_to_string(schema_path)
            .map_err(|e| anyhow::anyhow!("Failed to read schema file '{}': {}", schema_path, e))?;
        let parsed = parse_schema(&schema_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse schema '{}': {}", schema_path, e))?;
        log_initialized(&format!("Schema ({})", schema_path));
        Arc::new(parsed)
    } else {
        log_initialized("Schema (empty)");
        Arc::new(Schema::new(vec![]))
    };

    // Create the SigningKeyCache for Ledger-backed token validation
    use std::time::Duration;
    let signing_key_cache = Arc::new(SigningKeyCache::new(
        signing_key_store,
        Duration::from_secs(config.token.cache_ttl),
    ));
    log_initialized("Signing key cache");

    // Create server components
    let components = inferadb_engine_api::ServerComponents {
        store: Arc::clone(&store),
        schema: Arc::clone(&schema),
        wasm_host: wasm_host.clone(),
        config: Arc::clone(&config),
        signing_key_cache: Some(Arc::clone(&signing_key_cache)),
    };

    // Bind listener (address is already validated at config.validate())
    let listener = tokio::net::TcpListener::bind(&config.listen.http).await?;

    // Log ready status
    log_ready("Authorization Engine");

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Spawn task to handle shutdown signals
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });

    inferadb_engine_api::serve_public(components, listener, async move {
        shutdown_rx.recv().await.ok();
    })
    .await?;

    Ok(())
}

/// Graceful shutdown signal handler
#[allow(clippy::expect_used)] // Signal handler installation failure is unrecoverable
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
