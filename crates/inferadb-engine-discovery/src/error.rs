//! Error types for service discovery

use thiserror::Error;

/// Result type for service discovery operations
pub type Result<T> = std::result::Result<T, DiscoveryError>;

/// Errors that can occur during service discovery
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Kubernetes API error
    #[error("Kubernetes API error: {0}")]
    KubernetesApi(#[from] kube::Error),

    /// Invalid service URL
    #[error("Invalid service URL: {0}")]
    InvalidUrl(String),

    /// Service not found
    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    /// No endpoints available
    #[error("No endpoints available for service: {0}")]
    NoEndpoints(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Generic error
    #[error("Discovery error: {0}")]
    Other(String),
}

impl DiscoveryError {
    /// Create a new invalid URL error
    pub fn invalid_url(msg: impl Into<String>) -> Self {
        Self::InvalidUrl(msg.into())
    }

    /// Create a new service not found error
    pub fn service_not_found(name: impl Into<String>) -> Self {
        Self::ServiceNotFound(name.into())
    }

    /// Create a new no endpoints error
    pub fn no_endpoints(service: impl Into<String>) -> Self {
        Self::NoEndpoints(service.into())
    }

    /// Create a new configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a new generic error
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
