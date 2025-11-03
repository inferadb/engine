//! Authentication and authorization utility functions

use uuid::Uuid;

use crate::{ApiError, Result};

/// Extract vault from authentication context or use default
///
/// # Arguments
/// * `auth` - Optional authentication context
/// * `default_vault` - Default vault UUID to use if no auth context
///
/// # Returns
/// The vault UUID from the auth context, or the default vault
pub fn get_vault(auth: &Option<infera_types::AuthContext>, default_vault: Uuid) -> Uuid {
    auth.as_ref().map(|ctx| ctx.vault).unwrap_or(default_vault)
}

/// Check if the authenticated user has admin scope
///
/// Returns an error if:
/// - No authentication context present (401)
/// - User doesn't have the `inferadb.admin` scope (403)
///
/// # Arguments
/// * `auth` - Optional authentication context
///
/// # Returns
/// Ok(()) if user has admin scope, Err otherwise
pub fn require_admin_scope(auth: &Option<infera_types::AuthContext>) -> Result<()> {
    match auth {
        None => Err(ApiError::Unauthorized("Authentication required".to_string())),
        Some(ctx) => {
            if ctx.scopes.iter().any(|s| s == "inferadb.admin") {
                Ok(())
            } else {
                Err(ApiError::Forbidden(
                    "Admin scope (inferadb.admin) required for this operation".to_string(),
                ))
            }
        },
    }
}

/// Check if user has admin scope OR owns the specified account
///
/// This function implements authorization for account-scoped resources:
/// - Admins can access any account
/// - Users can only access their own account
///
/// # Arguments
/// * `auth` - Optional authentication context
/// * `account_id` - The account ID being accessed
///
/// # Returns
/// Ok(()) if authorized, Err otherwise
pub fn authorize_account_access(
    auth: &Option<infera_types::AuthContext>,
    account_id: Uuid,
) -> Result<()> {
    match auth {
        None => Err(ApiError::Unauthorized("Authentication required".to_string())),
        Some(ctx) => {
            // Admin can access any account
            if ctx.scopes.iter().any(|s| s == "inferadb.admin") {
                return Ok(());
            }
            // User can access their own account
            if ctx.account == account_id {
                return Ok(());
            }
            // Otherwise, deny
            Err(ApiError::Forbidden("Access denied to this account".to_string()))
        },
    }
}
