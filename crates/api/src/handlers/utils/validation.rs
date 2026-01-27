//! Input validation utilities
//!
//! This module provides validation functions for user-controlled input
//! to prevent injection attacks and ensure data integrity.

use crate::ApiError;

/// Validates that a type and ID pair do not contain special characters
/// that could be used for injection attacks.
///
/// # Arguments
///
/// * `type_` - The entity type (e.g., "user", "document")
/// * `id` - The entity ID (e.g., "alice", "doc-123")
///
/// # Errors
///
/// Returns `ApiError::InvalidRequest` if:
/// - Either `type_` or `id` contains a colon (`:`)
/// - Either `type_` or `id` is empty
///
/// # Security
///
/// This function prevents colon injection attacks where malicious input
/// like `"user:admin"` in the type field could bypass access controls
/// when concatenated into `"type:id"` format.
///
/// # Example
///
/// ```
/// use inferadb_engine_api::handlers::utils::validation::validate_type_id;
///
/// // Valid input
/// assert!(validate_type_id("user", "alice").is_ok());
///
/// // Invalid: contains colon
/// assert!(validate_type_id("user:admin", "alice").is_err());
/// assert!(validate_type_id("user", "alice:bob").is_err());
///
/// // Invalid: empty fields
/// assert!(validate_type_id("", "alice").is_err());
/// assert!(validate_type_id("user", "").is_err());
/// ```
pub fn validate_type_id(type_: &str, id: &str) -> Result<(), ApiError> {
    // Check for empty strings
    if type_.is_empty() {
        return Err(ApiError::InvalidRequest("Entity type cannot be empty".to_string()));
    }
    if id.is_empty() {
        return Err(ApiError::InvalidRequest("Entity ID cannot be empty".to_string()));
    }

    // Check for colon injection
    if type_.contains(':') {
        return Err(ApiError::InvalidRequest(format!(
            "Entity type cannot contain colons: '{}'",
            type_
        )));
    }
    if id.contains(':') {
        return Err(ApiError::InvalidRequest(format!("Entity ID cannot contain colons: '{}'", id)));
    }

    Ok(())
}

/// Validates and formats a type:id entity string safely
///
/// This is a convenience wrapper around `validate_type_id` that also
/// performs the string concatenation.
///
/// # Arguments
///
/// * `type_` - The entity type
/// * `id` - The entity ID
///
/// # Returns
///
/// A validated string in `"type:id"` format
///
/// # Errors
///
/// Returns `ApiError::InvalidRequest` if validation fails
///
/// # Example
///
/// ```
/// use inferadb_engine_api::handlers::utils::validation::safe_format_entity;
///
/// let entity = safe_format_entity("user", "alice").unwrap();
/// assert_eq!(entity, "user:alice");
///
/// // This would fail validation
/// assert!(safe_format_entity("user:admin", "alice").is_err());
/// ```
pub fn safe_format_entity(type_: &str, id: &str) -> Result<String, ApiError> {
    validate_type_id(type_, id)?;
    Ok(format!("{}:{}", type_, id))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_type_id_success() {
        assert!(validate_type_id("user", "alice").is_ok());
        assert!(validate_type_id("document", "doc-123").is_ok());
        assert!(validate_type_id("group", "admin_group").is_ok());
        assert!(validate_type_id("resource", "file/path.txt").is_ok());
    }

    #[test]
    fn test_validate_type_id_empty_type() {
        let result = validate_type_id("", "alice");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("type cannot be empty"));
    }

    #[test]
    fn test_validate_type_id_empty_id() {
        let result = validate_type_id("user", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ID cannot be empty"));
    }

    #[test]
    fn test_validate_type_id_colon_in_type() {
        let result = validate_type_id("user:admin", "alice");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot contain colons"));
    }

    #[test]
    fn test_validate_type_id_colon_in_id() {
        let result = validate_type_id("user", "alice:bob");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot contain colons"));
    }

    #[test]
    fn test_validate_type_id_multiple_colons() {
        let result = validate_type_id("user:group:admin", "alice:bob:charlie");
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_format_entity_success() {
        let entity = safe_format_entity("user", "alice").unwrap();
        assert_eq!(entity, "user:alice");

        let entity = safe_format_entity("document", "doc-123").unwrap();
        assert_eq!(entity, "document:doc-123");
    }

    #[test]
    fn test_safe_format_entity_injection_attempt() {
        // Attempt to inject "admin" role
        let result = safe_format_entity("user:admin", "alice");
        assert!(result.is_err());

        // Attempt to inject different entity
        let result = safe_format_entity("user", "alice:document:secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_format_entity_empty_fields() {
        assert!(safe_format_entity("", "alice").is_err());
        assert!(safe_format_entity("user", "").is_err());
        assert!(safe_format_entity("", "").is_err());
    }

    #[test]
    fn test_special_characters_allowed() {
        // Slashes, underscores, hyphens, dots should be fine
        assert!(validate_type_id("user", "alice/bob").is_ok());
        assert!(validate_type_id("user", "alice_bob").is_ok());
        assert!(validate_type_id("user", "alice-bob").is_ok());
        assert!(validate_type_id("user", "alice.bob").is_ok());
    }
}
