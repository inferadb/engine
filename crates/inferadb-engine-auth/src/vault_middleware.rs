use std::sync::Arc;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_engine_control_client::{VaultVerificationError, VaultVerifier};
use inferadb_engine_types::auth::AuthContext;
use tracing::{error, warn};

/// Middleware that validates vault ownership using VaultVerifier
///
/// This middleware verifies that the vault in the request belongs to the
/// authenticated organization by calling the Control API.
pub async fn control_verified_vault_middleware(
    vault_verifier: Arc<dyn VaultVerifier>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |req: Request, next: Next| {
        let verifier = vault_verifier.clone();
        Box::pin(async move {
            // Extract auth context from request extensions
            let auth_ctx = match req.extensions().get::<Arc<AuthContext>>() {
                Some(ctx) => ctx.clone(),
                None => {
                    // No auth context - let it through (auth middleware will handle)
                    return next.run(req).await;
                },
            };

            // Skip validation if vault is 0 (some endpoints don't require vault)
            if auth_ctx.vault == 0 {
                return next.run(req).await;
            }

            // Verify vault exists and belongs to organization
            match verifier.verify_vault(auth_ctx.vault, auth_ctx.organization).await {
                Ok(vault_info) => {
                    // Verify organization is active
                    if let Err(e) = verifier.verify_organization(vault_info.organization_id).await {
                        warn!(
                            vault_id = %auth_ctx.vault,
                            org_id = %vault_info.organization_id,
                            error = %e,
                            "Organization verification failed"
                        );
                        return (StatusCode::FORBIDDEN, "Organization is not active")
                            .into_response();
                    }

                    // All checks passed - continue
                    next.run(req).await
                },
                Err(e) => {
                    error!(
                        vault_id = %auth_ctx.vault,
                        organization_id = %auth_ctx.organization,
                        error = %e,
                        "Vault verification failed"
                    );

                    let (status, message) = match e {
                        VaultVerificationError::VaultNotFound(_) => {
                            (StatusCode::NOT_FOUND, "Vault not found")
                        },
                        VaultVerificationError::AccountMismatch { .. } => {
                            (StatusCode::FORBIDDEN, "Vault does not belong to this organization")
                        },
                        VaultVerificationError::OrganizationNotFound(_) => {
                            (StatusCode::NOT_FOUND, "Organization not found")
                        },
                        VaultVerificationError::OrganizationSuspended(_) => {
                            (StatusCode::FORBIDDEN, "Organization is suspended")
                        },
                        VaultVerificationError::ControlApiError(_) => {
                            (StatusCode::SERVICE_UNAVAILABLE, "Unable to verify vault")
                        },
                    };

                    (status, message).into_response()
                },
            }
        })
    }
}
