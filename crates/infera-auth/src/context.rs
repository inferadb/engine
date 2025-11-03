//! Re-export authentication types from infera-types for backwards compatibility
//!
//! AuthContext and AuthMethod have been moved to infera-types to prevent circular
//! dependencies and provide a stable foundation for shared types.

// Re-export types from infera-types
pub use infera_types::{AuthContext, AuthMethod};
