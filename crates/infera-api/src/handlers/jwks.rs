//! JWKS (JSON Web Key Set) endpoint handlers
//!
//! Provides the server's public key for JWT verification by the management API

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::{ApiError, AppState};

/// GET /.well-known/jwks.json
///
/// Returns the server's public key in JWKS format for JWT verification.
/// This endpoint is used by the management API to verify JWTs signed by this server.
pub async fn get_server_jwks(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state
        .server_identity
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Server identity not configured".to_string()))?;

    let jwks = identity.to_jwks();

    Ok((StatusCode::OK, Json(jwks)))
}
