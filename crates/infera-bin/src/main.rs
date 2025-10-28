//! # InferaDB Server Binary
//!
//! Main entrypoint for the InferaDB policy decision engine server.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use infera_config::load_or_default;
use infera_core::Evaluator;
use infera_core::ipl::Schema;
use infera_observe;
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

    let config = Arc::new(config);

    // Initialize storage backend
    // TODO: Support multiple backends based on config
    let store = Arc::new(MemoryBackend::new());
    tracing::info!("Using in-memory storage backend");

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
    let evaluator = Arc::new(Evaluator::new(store, schema, wasm_host));
    tracing::info!("Policy evaluator initialized");

    // Start API server
    tracing::info!(
        "Starting API server on {}:{}",
        config.server.host,
        config.server.port
    );

    infera_api::serve(evaluator, config).await?;

    Ok(())
}
