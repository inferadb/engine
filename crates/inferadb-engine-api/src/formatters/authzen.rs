//! Response formatting for AuthZEN endpoints
//!
//! This module provides centralized response formatting logic for AuthZEN protocol responses.
//! All formatting functions ensure consistent structure, localization, and compliance with
//! the AuthZEN specification.

use std::sync::atomic::{AtomicI64, Ordering};

use inferadb_engine_types::Decision;
use serde_json::{Value, json};

static ID_COUNTER: AtomicI64 = AtomicI64::new(1);

fn generate_id() -> i64 {
    ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Formats an AuthZEN evaluation response with decision and context
///
/// Creates a standardized response structure with:
/// - decision: boolean indicating allow/deny
/// - context: object with unique ID and localized reasoning
///
/// # Arguments
///
/// * `decision` - The native Decision enum (Allow/Deny)
/// * `subject` - Subject entity string (e.g., "user:alice")
/// * `permission` - Permission/action name (e.g., "view")
/// * `resource` - Resource entity string (e.g., "document:readme")
///
/// # Returns
///
/// A JSON Value containing the formatted response with decision and context
///
/// # Example
///
/// ```
/// use inferadb_engine_api::formatters::authzen::format_evaluation_response;
/// use inferadb_engine_types::Decision;
///
/// let response = format_evaluation_response(
///     Decision::Allow,
///     "user:alice",
///     "view",
///     "document:readme"
/// );
///
/// let obj = response.as_object().unwrap();
/// assert_eq!(obj.get("decision").unwrap().as_bool().unwrap(), true);
/// assert!(obj.get("context").is_some());
/// ```
pub fn format_evaluation_response(
    decision: Decision,
    subject: &str,
    permission: &str,
    resource: &str,
) -> Value {
    let decision_bool = matches!(decision, Decision::Allow);
    let evaluation_id = generate_id();

    let reason = if decision_bool {
        format!("{} has {} permission on {}", subject, permission, resource)
    } else {
        format!("{} does not have {} permission on {}", subject, permission, resource)
    };

    json!({
        "decision": decision_bool,
        "context": {
            "id": evaluation_id.to_string(),
            "reason_admin": {
                "en": reason
            }
        }
    })
}

/// Formats an AuthZEN evaluation response with custom context
///
/// Similar to `format_evaluation_response` but allows providing a custom context value.
/// Useful when you want to include additional fields in the context beyond the standard ones.
///
/// # Arguments
///
/// * `decision` - Boolean decision (true = allow, false = deny)
/// * `context` - Custom context object to include in the response
///
/// # Returns
///
/// A JSON Value containing the formatted response
///
/// # Example
///
/// ```
/// use inferadb_engine_api::formatters::authzen::format_evaluation_response_with_context;
/// use serde_json::json;
///
/// let custom_context = json!({
///     "id": "test-id",
///     "reason_admin": {
///         "en": "Custom reason"
///     },
///     "additional_field": "value"
/// });
///
/// let response = format_evaluation_response_with_context(true, custom_context);
///
/// let obj = response.as_object().unwrap();
/// assert_eq!(obj.get("decision").unwrap().as_bool().unwrap(), true);
/// ```
pub fn format_evaluation_response_with_context(decision: bool, context: Value) -> Value {
    json!({
        "decision": decision,
        "context": context
    })
}

/// Formats an error context object for AuthZEN responses
///
/// Creates a standardized error context with:
/// - id: unique identifier for the error
/// - reason_admin: localized error message
/// - error: machine-readable error message
///
/// # Arguments
///
/// * `error_message` - The error message to include
///
/// # Returns
///
/// A JSON Value containing the formatted error context
///
/// # Example
///
/// ```
/// use inferadb_engine_api::formatters::authzen::format_error_context;
///
/// let context = format_error_context("Invalid request: subject type cannot be empty");
///
/// let obj = context.as_object().unwrap();
/// assert!(obj.get("id").is_some());
/// assert!(obj.get("reason_admin").is_some());
/// assert!(obj.get("error").is_some());
/// ```
pub fn format_error_context(error_message: &str) -> Value {
    let error_id = generate_id();

    json!({
        "id": error_id.to_string(),
        "reason_admin": {
            "en": error_message
        },
        "error": error_message
    })
}

/// Formats a denial response with error context
///
/// Creates an AuthZEN evaluation response with decision=false and error context.
/// Useful for returning structured error responses in batch operations.
///
/// # Arguments
///
/// * `error_message` - The error message to include
///
/// # Returns
///
/// A JSON Value containing decision=false and error context
///
/// # Example
///
/// ```
/// use inferadb_engine_api::formatters::authzen::format_denial_with_error;
///
/// let response = format_denial_with_error("Validation error: empty subject type");
///
/// let obj = response.as_object().unwrap();
/// assert_eq!(obj.get("decision").unwrap().as_bool().unwrap(), false);
/// assert!(obj.get("context").unwrap().get("error").is_some());
/// ```
pub fn format_denial_with_error(error_message: &str) -> Value {
    json!({
        "decision": false,
        "context": format_error_context(error_message)
    })
}

/// Formats a localized reason_admin object
///
/// Creates a standardized localized message map with English as the default language.
/// Can be extended to support additional languages.
///
/// # Arguments
///
/// * `message` - The message text in English
///
/// # Returns
///
/// A JSON Value containing the localized message map
///
/// # Example
///
/// ```
/// use inferadb_engine_api::formatters::authzen::format_reason_admin;
///
/// let reason = format_reason_admin("Permission granted");
///
/// let obj = reason.as_object().unwrap();
/// assert_eq!(
///     obj.get("en").unwrap().as_str().unwrap(),
///     "Permission granted"
/// );
/// ```
pub fn format_reason_admin(message: &str) -> Value {
    json!({
        "en": message
    })
}

/// Creates a standardized context object with ID and reason
///
/// # Arguments
///
/// * `reason` - The reason message to include
///
/// # Returns
///
/// A JSON Value containing id and reason_admin
///
/// # Example
///
/// ```
/// use inferadb_engine_api::formatters::authzen::create_context_with_reason;
///
/// let context = create_context_with_reason("Access granted");
///
/// let obj = context.as_object().unwrap();
/// assert!(obj.get("id").is_some());
/// assert!(obj.get("reason_admin").is_some());
/// ```
pub fn create_context_with_reason(reason: &str) -> Value {
    let id = generate_id();

    json!({
        "id": id.to_string(),
        "reason_admin": format_reason_admin(reason)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_format_evaluation_response_allow() {
        let response =
            format_evaluation_response(Decision::Allow, "user:alice", "view", "document:readme");

        let obj = response.as_object().unwrap();
        assert!(obj.get("decision").unwrap().as_bool().unwrap());

        let context = obj.get("context").unwrap().as_object().unwrap();
        assert!(context.get("id").is_some());

        let reason_admin = context.get("reason_admin").unwrap().as_object().unwrap();
        let en = reason_admin.get("en").unwrap().as_str().unwrap();
        assert!(en.contains("user:alice"));
        assert!(en.contains("view"));
        assert!(en.contains("document:readme"));
        assert!(en.contains("has"));
    }

    #[test]
    fn test_format_evaluation_response_deny() {
        let response =
            format_evaluation_response(Decision::Deny, "user:bob", "edit", "document:secret");

        let obj = response.as_object().unwrap();
        assert!(!obj.get("decision").unwrap().as_bool().unwrap());

        let context = obj.get("context").unwrap().as_object().unwrap();
        assert!(context.get("id").is_some());

        let reason_admin = context.get("reason_admin").unwrap().as_object().unwrap();
        let en = reason_admin.get("en").unwrap().as_str().unwrap();
        assert!(en.contains("user:bob"));
        assert!(en.contains("edit"));
        assert!(en.contains("document:secret"));
        assert!(en.contains("does not have"));
    }

    #[test]
    fn test_format_evaluation_response_with_context() {
        let custom_context = json!({
            "id": "test-123",
            "reason_admin": {
                "en": "Custom reason"
            }
        });

        let response = format_evaluation_response_with_context(true, custom_context);

        let obj = response.as_object().unwrap();
        assert!(obj.get("decision").unwrap().as_bool().unwrap());

        let context = obj.get("context").unwrap().as_object().unwrap();
        assert_eq!(context.get("id").unwrap().as_str().unwrap(), "test-123");
    }

    #[test]
    fn test_format_error_context() {
        let context = format_error_context("Invalid subject type");

        let obj = context.as_object().unwrap();
        assert!(obj.get("id").is_some());

        let reason_admin = obj.get("reason_admin").unwrap().as_object().unwrap();
        assert_eq!(reason_admin.get("en").unwrap().as_str().unwrap(), "Invalid subject type");

        assert_eq!(obj.get("error").unwrap().as_str().unwrap(), "Invalid subject type");
    }

    #[test]
    fn test_format_denial_with_error() {
        let response = format_denial_with_error("Validation failed");

        let obj = response.as_object().unwrap();
        assert!(!obj.get("decision").unwrap().as_bool().unwrap());

        let context = obj.get("context").unwrap().as_object().unwrap();
        assert!(context.get("id").is_some());
        assert!(context.get("error").is_some());

        let reason_admin = context.get("reason_admin").unwrap().as_object().unwrap();
        assert_eq!(reason_admin.get("en").unwrap().as_str().unwrap(), "Validation failed");
    }

    #[test]
    fn test_format_reason_admin() {
        let reason = format_reason_admin("Access granted");

        let obj = reason.as_object().unwrap();
        assert_eq!(obj.get("en").unwrap().as_str().unwrap(), "Access granted");
    }

    #[test]
    fn test_create_context_with_reason() {
        let context = create_context_with_reason("Permission granted");

        let obj = context.as_object().unwrap();
        assert!(obj.get("id").is_some());

        let reason_admin = obj.get("reason_admin").unwrap().as_object().unwrap();
        assert_eq!(reason_admin.get("en").unwrap().as_str().unwrap(), "Permission granted");
    }

    #[test]
    fn test_evaluation_response_has_unique_ids() {
        let response1 =
            format_evaluation_response(Decision::Allow, "user:alice", "view", "document:readme");
        let response2 =
            format_evaluation_response(Decision::Allow, "user:alice", "view", "document:readme");

        let id1 = response1
            .as_object()
            .unwrap()
            .get("context")
            .unwrap()
            .get("id")
            .unwrap()
            .as_str()
            .unwrap();

        let id2 = response2
            .as_object()
            .unwrap()
            .get("context")
            .unwrap()
            .get("id")
            .unwrap()
            .as_str()
            .unwrap();

        assert_ne!(id1, id2, "Each response should have a unique ID");
    }

    #[test]
    fn test_error_context_has_unique_ids() {
        let context1 = format_error_context("Error 1");
        let context2 = format_error_context("Error 2");

        let id1 = context1.as_object().unwrap().get("id").unwrap().as_str().unwrap();
        let id2 = context2.as_object().unwrap().get("id").unwrap().as_str().unwrap();

        assert_ne!(id1, id2, "Each error context should have a unique ID");
    }

    #[test]
    fn test_reason_admin_is_localized() {
        let context = create_context_with_reason("Test message");

        let obj = context.as_object().unwrap();
        let reason_admin = obj.get("reason_admin").unwrap().as_object().unwrap();

        // Should have at least English
        assert!(reason_admin.contains_key("en"));
        assert_eq!(reason_admin.get("en").unwrap().as_str().unwrap(), "Test message");
    }
}
