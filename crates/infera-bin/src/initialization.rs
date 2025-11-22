//! System initialization module
//!
//! Handles first-startup initialization of default Organization and Vault.
//!
//! # Initialization Flow
//!
//! 1. Check if SystemConfig exists in database
//! 2. If exists, return existing config (already initialized)
//! 3. If not, check if config file has default_vault and default_organization
//! 4. If config has values, use them (create organization/vault if needed)
//! 5. If no config values, auto-generate new organization and vault
//! 6. Store SystemConfig in database
//! 7. Return SystemConfig for use in server
//!
//! # Example
//!
//! ```rust,no_run
//! use infera_store::InferaStore;
//! use infera_config::Config;
//! use std::sync::Arc;
//! use infera_bin::initialization;
//!
//! # #[tokio::main]
//! # async fn main() {
//! # let store: Arc<dyn InferaStore> = Arc::new(infera_store::MemoryBackend::new());
//! # let config = Config::default();
//! let system_config = initialization::initialize_system(&store, &config)
//!     .await
//!     .expect("Failed to initialize system");
//!
//! println!("Using vault: {}", system_config.default_vault);
//! println!("Using organization: {}", system_config.default_organization);
//! # }
//! ```

use std::sync::Arc;

use anyhow::{Context, Result};
use infera_config::Config;
use infera_store::InferaStore;
use infera_types::{Organization, SystemConfig, Vault};

/// Initialize system on first startup
///
/// This function is idempotent and safe to call on every startup.
/// It will:
/// - Return existing SystemConfig if already initialized
/// - Use config file values if present
/// - Auto-generate defaults if no config exists
/// - Create Organization and Vault as needed
/// - Persist SystemConfig to database
///
/// # Arguments
///
/// * `store` - Storage backend (MemoryBackend or FoundationDB)
/// * `config` - Application configuration
///
/// # Returns
///
/// SystemConfig with default_organization and default_vault UUIDs
///
/// # Errors
///
/// Returns error if:
/// - Database operations fail
/// - UUID parsing fails
/// - Organization/Vault creation fails
pub async fn initialize_system(
    store: &Arc<dyn InferaStore>,
    config: &Config,
) -> Result<SystemConfig> {
    // 1. Check if system config already exists in database
    if let Some(existing_config) =
        store.get_system_config().await.context("Failed to check for existing system config")?
    {
        tracing::info!(
            organization_id = %existing_config.default_organization,
            vault_id = %existing_config.default_vault,
            "System already initialized"
        );
        return Ok(existing_config);
    }

    // 2. Check if config file has default values
    if let (Some(organization_str), Some(vault_str)) =
        (&config.multi_tenancy.default_account, &config.multi_tenancy.default_vault)
    {
        tracing::info!(
            organization_str = %organization_str,
            vault_str = %vault_str,
            "Using default vault and organization from configuration"
        );

        // Parse i64 IDs from config
        let organization_id: i64 = organization_str
            .parse()
            .context("Failed to parse default_organization ID from config")?;
        let vault_id: i64 =
            vault_str.parse().context("Failed to parse default_vault ID from config")?;

        // Ensure organization exists (create if needed)
        ensure_organization_exists(store, organization_id, "Default Organization")
            .await
            .context("Failed to ensure organization exists")?;

        // Ensure vault exists (create if needed)
        ensure_vault_exists(store, vault_id, organization_id, "Default Vault")
            .await
            .context("Failed to ensure vault exists")?;

        // Store system config
        let system_config = SystemConfig::new(organization_id, vault_id);
        store
            .set_system_config(system_config.clone())
            .await
            .context("Failed to store system config")?;

        tracing::info!(
            organization_id = %organization_id,
            vault_id = %vault_id,
            "System initialized from configuration"
        );

        return Ok(system_config);
    }

    // 3. No config exists - create new defaults
    tracing::info!("First startup detected - creating default organization and vault");

    let organization = create_default_organization(store)
        .await
        .context("Failed to create default organization")?;

    let vault = create_default_vault(store, organization.id)
        .await
        .context("Failed to create default vault")?;

    let system_config = SystemConfig::new(organization.id, vault.id);
    store
        .set_system_config(system_config.clone())
        .await
        .context("Failed to store system config")?;

    tracing::info!(
        organization_id = %organization.id,
        vault_id = %vault.id,
        organization_name = %organization.name,
        vault_name = %vault.name,
        "System initialized with auto-generated defaults"
    );

    Ok(system_config)
}

/// Create a new default organization
///
/// Creates an organization with the name "Default Organization" and ID 1.
async fn create_default_organization(store: &Arc<dyn InferaStore>) -> Result<Organization> {
    let organization = Organization::new(1, "Default Organization".to_string());

    tracing::info!(
        organization_id = %organization.id,
        organization_name = %organization.name,
        "Creating default organization"
    );

    store
        .create_organization(organization.clone())
        .await
        .context("Failed to create organization")?;

    Ok(organization)
}

/// Create a new default vault for the given organization
///
/// Creates a vault with the name "Default Vault" and ID 1.
async fn create_default_vault(store: &Arc<dyn InferaStore>, organization_id: i64) -> Result<Vault> {
    let vault = Vault::new(1, organization_id, "Default Vault".to_string());

    tracing::info!(
        vault_id = %vault.id,
        vault_name = %vault.name,
        organization_id = %organization_id,
        "Creating default vault"
    );

    store.create_vault(vault.clone()).await.context("Failed to create vault")?;

    Ok(vault)
}

/// Ensure an organization with the given ID exists, creating it if needed
///
/// # Arguments
///
/// * `store` - Storage backend
/// * `organization_id` - ID of the organization to ensure exists
/// * `name` - Name to use if creating the organization
async fn ensure_organization_exists(
    store: &Arc<dyn InferaStore>,
    organization_id: i64,
    name: &str,
) -> Result<()> {
    // Check if organization already exists
    if let Some(existing) = store
        .get_organization(organization_id)
        .await
        .context("Failed to check if organization exists")?
    {
        tracing::debug!(
            organization_id = %organization_id,
            organization_name = %existing.name,
            "Organization already exists"
        );
        return Ok(());
    }

    // Create organization with specified ID
    let organization = Organization::with_id(organization_id, name.to_string());

    tracing::info!(
        organization_id = %organization_id,
        organization_name = %name,
        "Creating organization from configuration"
    );

    store.create_organization(organization).await.context("Failed to create organization")?;

    Ok(())
}

/// Ensure a vault with the given ID exists, creating it if needed
///
/// # Arguments
///
/// * `store` - Storage backend
/// * `vault_id` - ID of the vault to ensure exists
/// * `organization_id` - Organization that should own the vault
/// * `name` - Name to use if creating the vault
async fn ensure_vault_exists(
    store: &Arc<dyn InferaStore>,
    vault_id: i64,
    organization_id: i64,
    name: &str,
) -> Result<()> {
    // Check if vault already exists
    if let Some(existing) =
        store.get_vault(vault_id).await.context("Failed to check if vault exists")?
    {
        tracing::debug!(
            vault_id = %vault_id,
            vault_name = %existing.name,
            organization_id = %existing.organization,
            "Vault already exists"
        );

        // Verify vault belongs to expected organization
        if existing.organization != organization_id {
            anyhow::bail!(
                "Vault {} belongs to organization {}, expected organization {}",
                vault_id,
                existing.organization,
                organization_id
            );
        }

        return Ok(());
    }

    // Create vault with specified ID
    let vault = Vault::with_id(vault_id, organization_id, name.to_string());

    tracing::info!(
        vault_id = %vault_id,
        vault_name = %name,
        organization_id = %organization_id,
        "Creating vault from configuration"
    );

    store.create_vault(vault).await.context("Failed to create vault")?;

    Ok(())
}
