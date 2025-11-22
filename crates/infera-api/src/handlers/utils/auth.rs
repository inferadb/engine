//! Authentication and authorization utility functions

use infera_const::scopes::*;

use crate::{ApiError, Result};

/// Extract vault from authentication context or use default
///
/// # Arguments
/// * `auth` - Optional authentication context
/// * `default_vault` - Default vault ID to use if no auth context
///
/// # Returns
/// The vault ID from the auth context, or the default vault
pub fn get_vault(auth: &Option<infera_types::AuthContext>, default_vault: i64) -> i64 {
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
            if ctx.scopes.iter().any(|s| s == SCOPE_ADMIN) {
                Ok(())
            } else {
                Err(ApiError::Forbidden(format!(
                    "Admin scope ({}) required for this operation",
                    SCOPE_ADMIN
                )))
            }
        },
    }
}

/// Check if user has admin scope OR owns the specified organization
///
/// This function implements authorization for organization-scoped resources:
/// - Admins can access any organization
/// - Users can only access their own organization
///
/// # Arguments
/// * `auth` - Optional authentication context
/// * `organization_id` - The organization ID being accessed
///
/// # Returns
/// Ok(()) if authorized, Err otherwise
pub fn authorize_organization_access(
    auth: &Option<infera_types::AuthContext>,
    organization_id: i64,
) -> Result<()> {
    match auth {
        None => Err(ApiError::Unauthorized("Authentication required".to_string())),
        Some(ctx) => {
            // Admin can access any organization
            if ctx.scopes.iter().any(|s| s == SCOPE_ADMIN) {
                return Ok(());
            }
            // User can access their own organization
            if ctx.organization == organization_id {
                return Ok(());
            }
            // Otherwise, deny
            Err(ApiError::Forbidden("Access denied to this organization".to_string()))
        },
    }
}

/// Authorize request with vault extraction, validation, and scope checking
///
/// This helper consolidates the common authentication/authorization pattern used
/// across handlers. It handles:
/// 1. Vault extraction from auth context or default
/// 2. Vault access validation (nil UUID check)
/// 3. Authentication requirement when auth is enabled
/// 4. Scope validation (single or multiple scopes)
///
/// This replaces 15-25 lines of duplicated code in each handler.
///
/// # Arguments
/// * `auth` - Optional authentication context from request
/// * `default_vault` - Default vault UUID to use if no auth context
/// * `auth_enabled` - Whether authentication is enabled in config
/// * `scopes` - Required scopes (empty slice = no scope check)
///
/// # Returns
/// Ok(vault) if authorized, Err otherwise
///
/// # Examples
///
/// ```ignore
/// // Single scope requirement
/// let vault = authorize_request(
///     &auth.0,
///     state.default_vault,
///     state.config.auth.enabled,
///     &[SCOPE_CHECK]
/// )?;
/// ```
///
/// ```ignore
/// // Multiple scopes (any of them)
/// let vault = authorize_request(
///     &auth.0,
///     state.default_vault,
///     state.config.auth.enabled,
///     &[SCOPE_EXPAND, SCOPE_CHECK]
/// )?;
/// ```
///
/// ```ignore
/// // No scope check (just auth + vault validation)
/// let vault = authorize_request(
///     &auth.0,
///     state.default_vault,
///     state.config.auth.enabled,
///     &[]
/// )?;
/// ```
pub fn authorize_request(
    auth: &Option<infera_types::AuthContext>,
    default_vault: i64,
    auth_enabled: bool,
    scopes: &[&str],
) -> Result<i64> {
    // Extract vault from auth context or use default
    let vault = get_vault(auth, default_vault);

    // Validate vault access (basic nil check)
    if let Some(ref auth_ctx) = auth {
        infera_auth::validate_vault_access(auth_ctx)
            .map_err(|e| ApiError::Forbidden(format!("Vault access denied: {}", e)))?;
    }

    // If auth is enabled, require authentication and validate scopes
    if auth_enabled {
        match auth {
            Some(auth_ctx) => {
                // Validate scope(s) if any are specified
                if !scopes.is_empty() {
                    if scopes.len() == 1 {
                        // Single scope requirement
                        infera_auth::middleware::require_scope(auth_ctx, scopes[0])
                            .map_err(|e| ApiError::Forbidden(e.to_string()))?;
                    } else {
                        // Multiple scopes - require any of them
                        infera_auth::middleware::require_any_scope(auth_ctx, scopes)
                            .map_err(|e| ApiError::Forbidden(e.to_string()))?;
                    }
                }
                Ok(vault)
            },
            None => Err(ApiError::Unauthorized("Authentication required".to_string())),
        }
    } else {
        // Auth not enabled - allow request
        Ok(vault)
    }
}

#[cfg(test)]
mod tests {
    use infera_types::AuthMethod;

    use super::*;

    fn create_test_auth_context(scopes: Vec<String>) -> infera_types::AuthContext {
        infera_types::AuthContext {
            tenant_id: "test_tenant".to_string(),
            client_id: "test_client".to_string(),
            key_id: "test_key".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: None,
            vault: 1,
            organization: 2,
        }
    }

    #[test]
    fn test_authorize_request_with_auth_and_valid_scope() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);
        let default_vault = 99i64;

        let result =
            authorize_request(&Some(auth_ctx.clone()), default_vault, true, &[SCOPE_CHECK]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), auth_ctx.vault);
    }

    #[test]
    fn test_authorize_request_uses_auth_vault_not_default() {
        let auth_vault = 1i64;
        let default_vault = 99i64;

        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);

        let result = authorize_request(&Some(auth_ctx), default_vault, true, &[SCOPE_CHECK]);

        assert!(result.is_ok());
        let vault = result.unwrap();
        assert_eq!(vault, auth_vault);
        assert_ne!(vault, default_vault);
    }

    #[test]
    fn test_authorize_request_with_auth_and_invalid_scope() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_READ.to_string()]);
        let default_vault = 0i64;

        let result = authorize_request(&Some(auth_ctx), default_vault, true, &[SCOPE_WRITE]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
    }

    #[test]
    fn test_authorize_request_with_multiple_scopes_any_match() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);
        let default_vault = 0i64;

        let result =
            authorize_request(&Some(auth_ctx), default_vault, true, &[SCOPE_EXPAND, SCOPE_CHECK]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_request_with_multiple_scopes_none_match() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_ADMIN.to_string()]);
        let default_vault = 0i64;

        let result =
            authorize_request(&Some(auth_ctx), default_vault, true, &[SCOPE_EXPAND, SCOPE_CHECK]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
    }

    #[test]
    fn test_authorize_request_no_auth_when_required() {
        let default_vault = 0i64;

        let result = authorize_request(&None, default_vault, true, &[SCOPE_CHECK]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Unauthorized(_)));
    }

    #[test]
    fn test_authorize_request_no_auth_when_not_required() {
        let default_vault = 99i64;

        let result = authorize_request(&None, default_vault, false, &[]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), default_vault);
    }

    #[test]
    fn test_authorize_request_empty_scopes() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);
        let default_vault = 0i64;

        // Empty scopes = no scope check required
        let result = authorize_request(&Some(auth_ctx), default_vault, true, &[]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_request_nil_vault_rejected() {
        let mut auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);
        auth_ctx.vault = 0i64;
        let default_vault = 99i64;

        let result = authorize_request(&Some(auth_ctx), default_vault, true, &[SCOPE_CHECK]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
    }

    #[test]
    fn test_get_vault_with_auth() {
        let vault = 1i64;
        let default_vault = 99i64;
        let mut auth_ctx = create_test_auth_context(vec![]);
        auth_ctx.vault = vault;

        let result = get_vault(&Some(auth_ctx), default_vault);

        assert_eq!(result, vault);
    }

    #[test]
    fn test_get_vault_without_auth_uses_default() {
        let default_vault = 99i64;

        let result = get_vault(&None, default_vault);

        assert_eq!(result, default_vault);
    }

    #[test]
    fn test_require_admin_scope_with_admin() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_ADMIN.to_string()]);

        let result = require_admin_scope(&Some(auth_ctx));

        assert!(result.is_ok());
    }

    #[test]
    fn test_require_admin_scope_without_admin() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);

        let result = require_admin_scope(&Some(auth_ctx));

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
    }

    #[test]
    fn test_require_admin_scope_no_auth() {
        let result = require_admin_scope(&None);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Unauthorized(_)));
    }

    #[test]
    fn test_authorize_organization_access_as_admin() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_ADMIN.to_string()]);
        let organization_id = 999i64;

        let result = authorize_organization_access(&Some(auth_ctx), organization_id);

        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_organization_access_as_owner() {
        let organization_id = 2i64;
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);

        let result = authorize_organization_access(&Some(auth_ctx), organization_id);

        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_organization_access_denied() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);
        let other_organization = 888i64;

        let result = authorize_organization_access(&Some(auth_ctx), other_organization);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
    }

    #[test]
    fn test_authorize_organization_access_no_auth() {
        let organization_id = 777i64;

        let result = authorize_organization_access(&None, organization_id);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Unauthorized(_)));
    }
}
