//! Account management handlers
//!
//! Provides REST API endpoints for managing Accounts.
//! Accounts own Vaults and provide the top-level tenant isolation boundary.

pub mod create;
pub mod delete;
pub mod get;
pub mod list;
pub mod update;
