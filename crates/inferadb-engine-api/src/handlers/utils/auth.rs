//! Authentication and authorization utility functions

use inferadb_engine_const::scopes::*;

use crate::{ApiError, Result};

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
pub fn require_admin_scope(auth: &Option<inferadb_engine_types::AuthContext>) -> Result<()> {
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
    auth: &Option<inferadb_engine_types::AuthContext>,
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
/// 1. Vault extraction from auth context (authentication required)
/// 2. Vault access validation (nil UUID check)
/// 3. Scope validation (single or multiple scopes)
///
/// This replaces 15-25 lines of duplicated code in each handler.
///
/// # Arguments
/// * `auth` - Optional authentication context from request
/// * `scopes` - Required scopes (empty slice = no scope check)
///
/// # Returns
/// Ok(vault) if authorized, Err otherwise
///
/// # Examples
///
/// ```ignore
/// // Single scope requirement
/// let vault = authorize_request(&auth.0, &[SCOPE_CHECK])?;
/// ```
///
/// ```ignore
/// // Multiple scopes (any of them)
/// let vault = authorize_request(&auth.0, &[SCOPE_EXPAND, SCOPE_CHECK])?;
/// ```
///
/// ```ignore
/// // No scope check (just auth + vault validation)
/// let vault = authorize_request(&auth.0, &[])?;
/// ```
pub fn authorize_request(
    auth: &Option<inferadb_engine_types::AuthContext>,
    scopes: &[&str],
) -> Result<i64> {
    // Always require authentication
    match auth {
        Some(auth_ctx) => {
            // Extract vault from auth context
            let vault = auth_ctx.vault;

            // Validate vault access (basic nil check)
            inferadb_engine_auth::validate_vault_access(auth_ctx)
                .map_err(|e| ApiError::Forbidden(format!("Vault access denied: {}", e)))?;

            // Validate scope(s) if any are specified
            if !scopes.is_empty() {
                if scopes.len() == 1 {
                    // Single scope requirement
                    inferadb_engine_auth::middleware::require_scope(auth_ctx, scopes[0])
                        .map_err(|e| ApiError::Forbidden(e.to_string()))?;
                } else {
                    // Multiple scopes - require any of them
                    inferadb_engine_auth::middleware::require_any_scope(auth_ctx, scopes)
                        .map_err(|e| ApiError::Forbidden(e.to_string()))?;
                }
            }
            Ok(vault)
        },
        None => Err(ApiError::Unauthorized("Authentication required".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use inferadb_engine_types::AuthMethod;

    use super::*;

    fn create_test_auth_context(scopes: Vec<String>) -> inferadb_engine_types::AuthContext {
        inferadb_engine_types::AuthContext {
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

        let result = authorize_request(&Some(auth_ctx.clone()), &[SCOPE_CHECK]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), auth_ctx.vault);
    }

    #[test]
    fn test_authorize_request_uses_auth_vault() {
        let auth_vault = 1i64;

        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);

        let result = authorize_request(&Some(auth_ctx), &[SCOPE_CHECK]);

        assert!(result.is_ok());
        let vault = result.unwrap();
        assert_eq!(vault, auth_vault);
    }

    #[test]
    fn test_authorize_request_with_auth_and_invalid_scope() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_READ.to_string()]);

        let result = authorize_request(&Some(auth_ctx), &[SCOPE_WRITE]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
    }

    #[test]
    fn test_authorize_request_with_multiple_scopes_any_match() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);

        let result = authorize_request(&Some(auth_ctx), &[SCOPE_EXPAND, SCOPE_CHECK]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_request_with_multiple_scopes_none_match() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_ADMIN.to_string()]);

        let result = authorize_request(&Some(auth_ctx), &[SCOPE_EXPAND, SCOPE_CHECK]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
    }

    #[test]
    fn test_authorize_request_no_auth() {
        let result = authorize_request(&None, &[SCOPE_CHECK]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Unauthorized(_)));
    }

    #[test]
    fn test_authorize_request_empty_scopes() {
        let auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);

        // Empty scopes = no scope check required
        let result = authorize_request(&Some(auth_ctx), &[]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_request_nil_vault_rejected() {
        let mut auth_ctx = create_test_auth_context(vec![SCOPE_CHECK.to_string()]);
        auth_ctx.vault = 0i64;

        let result = authorize_request(&Some(auth_ctx), &[SCOPE_CHECK]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Forbidden(_)));
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
