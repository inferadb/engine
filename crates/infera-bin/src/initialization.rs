//! System initialization module
//!
//! Handles first-startup initialization of default Account and Vault.
//!
//! # Initialization Flow
//!
//! 1. Check if SystemConfig exists in database
//! 2. If exists, return existing config (already initialized)
//! 3. If not, check if config file has default_vault and default_account
//! 4. If config has values, use them (create account/vault if needed)
//! 5. If no config values, auto-generate new account and vault
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
//! println!("Using account: {}", system_config.default_account);
//! # }
//! ```

use std::sync::Arc;

use anyhow::{Context, Result};
use infera_config::Config;
use infera_store::InferaStore;
use infera_types::{Account, SystemConfig, Vault};

/// Initialize system on first startup
///
/// This function is idempotent and safe to call on every startup.
/// It will:
/// - Return existing SystemConfig if already initialized
/// - Use config file values if present
/// - Auto-generate defaults if no config exists
/// - Create Account and Vault as needed
/// - Persist SystemConfig to database
///
/// # Arguments
///
/// * `store` - Storage backend (MemoryBackend or FoundationDB)
/// * `config` - Application configuration
///
/// # Returns
///
/// SystemConfig with default_account and default_vault UUIDs
///
/// # Errors
///
/// Returns error if:
/// - Database operations fail
/// - UUID parsing fails
/// - Account/Vault creation fails
pub async fn initialize_system(
    store: &Arc<dyn InferaStore>,
    config: &Config,
) -> Result<SystemConfig> {
    // 1. Check if system config already exists in database
    if let Some(existing_config) =
        store.get_system_config().await.context("Failed to check for existing system config")?
    {
        tracing::info!(
            account_id = %existing_config.default_account,
            vault_id = %existing_config.default_vault,
            "System already initialized"
        );
        return Ok(existing_config);
    }

    // 2. Check if config file has default values
    if let (Some(account_str), Some(vault_str)) =
        (&config.multi_tenancy.default_account, &config.multi_tenancy.default_vault)
    {
        tracing::info!(
            account_str = %account_str,
            vault_str = %vault_str,
            "Using default vault and account from configuration"
        );

        // Parse i64 IDs from config
        let account_id: i64 = account_str
            .parse()
            .context("Failed to parse default_account ID from config")?;
        let vault_id: i64 = vault_str
            .parse()
            .context("Failed to parse default_vault ID from config")?;

        // Ensure account exists (create if needed)
        ensure_account_exists(store, account_id, "Default Account")
            .await
            .context("Failed to ensure account exists")?;

        // Ensure vault exists (create if needed)
        ensure_vault_exists(store, vault_id, account_id, "Default Vault")
            .await
            .context("Failed to ensure vault exists")?;

        // Store system config
        let system_config = SystemConfig::new(account_id, vault_id);
        store
            .set_system_config(system_config.clone())
            .await
            .context("Failed to store system config")?;

        tracing::info!(
            account_id = %account_id,
            vault_id = %vault_id,
            "System initialized from configuration"
        );

        return Ok(system_config);
    }

    // 3. No config exists - create new defaults
    tracing::info!("First startup detected - creating default account and vault");

    let account =
        create_default_account(store).await.context("Failed to create default account")?;

    let vault =
        create_default_vault(store, account.id).await.context("Failed to create default vault")?;

    let system_config = SystemConfig::new(account.id, vault.id);
    store
        .set_system_config(system_config.clone())
        .await
        .context("Failed to store system config")?;

    tracing::info!(
        account_id = %account.id,
        vault_id = %vault.id,
        account_name = %account.name,
        vault_name = %vault.name,
        "System initialized with auto-generated defaults"
    );

    Ok(system_config)
}

/// Create a new default account
///
/// Creates an account with the name "Default Account" and ID 1.
async fn create_default_account(store: &Arc<dyn InferaStore>) -> Result<Account> {
    let account = Account::new(1, "Default Account".to_string());

    tracing::info!(
        account_id = %account.id,
        account_name = %account.name,
        "Creating default account"
    );

    store.create_account(account.clone()).await.context("Failed to create account")?;

    Ok(account)
}

/// Create a new default vault for the given account
///
/// Creates a vault with the name "Default Vault" and ID 1.
async fn create_default_vault(store: &Arc<dyn InferaStore>, account_id: i64) -> Result<Vault> {
    let vault = Vault::new(1, account_id, "Default Vault".to_string());

    tracing::info!(
        vault_id = %vault.id,
        vault_name = %vault.name,
        account_id = %account_id,
        "Creating default vault"
    );

    store.create_vault(vault.clone()).await.context("Failed to create vault")?;

    Ok(vault)
}

/// Ensure an account with the given ID exists, creating it if needed
///
/// # Arguments
///
/// * `store` - Storage backend
/// * `account_id` - ID of the account to ensure exists
/// * `name` - Name to use if creating the account
async fn ensure_account_exists(
    store: &Arc<dyn InferaStore>,
    account_id: i64,
    name: &str,
) -> Result<()> {
    // Check if account already exists
    if let Some(existing) =
        store.get_account(account_id).await.context("Failed to check if account exists")?
    {
        tracing::debug!(
            account_id = %account_id,
            account_name = %existing.name,
            "Account already exists"
        );
        return Ok(());
    }

    // Create account with specified ID
    let account = Account::with_id(account_id, name.to_string());

    tracing::info!(
        account_id = %account_id,
        account_name = %name,
        "Creating account from configuration"
    );

    store.create_account(account).await.context("Failed to create account")?;

    Ok(())
}

/// Ensure a vault with the given ID exists, creating it if needed
///
/// # Arguments
///
/// * `store` - Storage backend
/// * `vault_id` - ID of the vault to ensure exists
/// * `account_id` - Account that should own the vault
/// * `name` - Name to use if creating the vault
async fn ensure_vault_exists(
    store: &Arc<dyn InferaStore>,
    vault_id: i64,
    account_id: i64,
    name: &str,
) -> Result<()> {
    // Check if vault already exists
    if let Some(existing) =
        store.get_vault(vault_id).await.context("Failed to check if vault exists")?
    {
        tracing::debug!(
            vault_id = %vault_id,
            vault_name = %existing.name,
            account_id = %existing.account,
            "Vault already exists"
        );

        // Verify vault belongs to expected account
        if existing.account != account_id {
            anyhow::bail!(
                "Vault {} belongs to account {}, expected account {}",
                vault_id,
                existing.account,
                account_id
            );
        }

        return Ok(());
    }

    // Create vault with specified ID
    let vault = Vault::with_id(vault_id, account_id, name.to_string());

    tracing::info!(
        vault_id = %vault_id,
        vault_name = %name,
        account_id = %account_id,
        "Creating vault from configuration"
    );

    store.create_vault(vault).await.context("Failed to create vault")?;

    Ok(())
}
