//! Error types for Control client operations

/// Errors that can occur when interacting with Control
#[derive(Debug, thiserror::Error)]
pub enum ControlClientError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    /// Invalid response from Control
    #[error("Invalid response from Control: {0}")]
    InvalidResponse(String),

    /// Resource not found
    #[error("{0} not found")]
    NotFound(&'static str),

    /// Unexpected HTTP status code
    #[error("Unexpected HTTP status: {0}")]
    UnexpectedStatus(u16),

    /// JWT signing error
    #[error("JWT signing error: {0}")]
    JwtSigningError(String),

    /// Identity error
    #[error("Identity error: {0}")]
    IdentityError(String),
}
