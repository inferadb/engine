//! # InferaDB Constants
//!
//! Centralized constants used across the InferaDB codebase.
//! This crate provides a single source of truth for magic numbers and strings.

// ============================================================================
// Pagination Constants
// ============================================================================

/// Default limit for paginated list operations
///
/// Used by:
/// - ListRelationships API
/// - ListSubjects API
/// - ListResources API
pub const DEFAULT_LIST_LIMIT: usize = 100;

/// Maximum limit for paginated list operations
///
/// Used by:
/// - ListRelationships API
/// - ListSubjects API
/// - ListResources API
pub const MAX_LIST_LIMIT: usize = 1000;

// ============================================================================
// Change Feed Constants
// ============================================================================

/// Default channel capacity for change feed subscriptions
///
/// This controls the buffer size for the broadcast channel used in
/// the replication change feed. Subscribers that fall behind by more
/// than this amount will experience lag errors and need to resync.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 1000;

// ============================================================================
// Delete Operation Constants
// ============================================================================

/// Default limit for bulk delete operations
///
/// This is a safety limit to prevent accidental mass deletion.
/// Users can override this by explicitly setting limit=0 for unlimited.
pub const DEFAULT_DELETE_LIMIT: usize = 1000;
