//! AuthZEN protocol adapter
//!
//! Provides bidirectional translation between AuthZEN's structured entity format
//! and InferaDB's native type:id string format.
//!
//! # Format
//!
//! AuthZEN uses structured entities:
//! ```json
//! {"type": "user", "id": "alice"}
//! ```
//!
//! InferaDB uses type:id strings:
//! ```
//! "user:alice"
//! ```
//!
//! # Validation Rules
//!
//! - Type: Must match `^[a-z_][a-z0-9_]*$` (lowercase letters, numbers, underscores; must start with letter or underscore)
//! - ID: Must match `^[a-z0-9_-]+$` (lowercase letters, numbers, underscores, hyphens)
//! - Neither type nor id can be empty
//! - The string format must contain exactly one colon separator

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during entity parsing or formatting
#[derive(Debug, Error, PartialEq)]
pub enum EntityError {
    #[error("Invalid format: expected 'type:id' but got '{0}'")]
    InvalidFormat(String),

    #[error("Empty type in entity")]
    EmptyType,

    #[error("Empty id in entity")]
    EmptyId,

    #[error("Invalid type '{0}': must match pattern ^[a-z_][a-z0-9_]*$")]
    InvalidType(String),

    #[error("Invalid id '{0}': must match pattern ^[a-z0-9_-]+$")]
    InvalidId(String),
}

/// AuthZEN entity representation with separate type and id fields
///
/// This matches the AuthZEN specification's entity format:
/// ```json
/// {
///   "type": "user",
///   "id": "alice"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthZENEntity {
    /// Entity type (e.g., "user", "document", "team")
    #[serde(rename = "type")]
    pub entity_type: String,

    /// Entity identifier (e.g., "alice", "doc-123")
    pub id: String,
}

impl AuthZENEntity {
    /// Creates a new AuthZENEntity with validation
    pub fn new(entity_type: String, id: String) -> Result<Self, EntityError> {
        validate_type(&entity_type)?;
        validate_id(&id)?;
        Ok(Self { entity_type, id })
    }
}

/// Validates that a type string matches the required format
fn validate_type(type_str: &str) -> Result<(), EntityError> {
    if type_str.is_empty() {
        return Err(EntityError::EmptyType);
    }

    // Type must match: ^[a-z_][a-z0-9_]*$
    // - Start with lowercase letter or underscore
    // - Followed by zero or more lowercase letters, digits, or underscores
    let first_char = type_str.chars().next().unwrap();
    if !first_char.is_ascii_lowercase() && first_char != '_' {
        return Err(EntityError::InvalidType(type_str.to_string()));
    }

    for ch in type_str.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '_' {
            return Err(EntityError::InvalidType(type_str.to_string()));
        }
    }

    Ok(())
}

/// Validates that an id string matches the required format
fn validate_id(id_str: &str) -> Result<(), EntityError> {
    if id_str.is_empty() {
        return Err(EntityError::EmptyId);
    }

    // ID must match: ^[a-z0-9_-]+$
    // - One or more lowercase letters, digits, underscores, or hyphens
    for ch in id_str.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '_' && ch != '-' {
            return Err(EntityError::InvalidId(id_str.to_string()));
        }
    }

    Ok(())
}

/// Parses an InferaDB type:id string into an AuthZEN entity
///
/// # Examples
///
/// ```
/// # use infera_api::adapters::authzen::{parse_entity, AuthZENEntity};
/// let entity = parse_entity("user:alice").unwrap();
/// assert_eq!(entity.entity_type, "user");
/// assert_eq!(entity.id, "alice");
///
/// let entity = parse_entity("team:engineering").unwrap();
/// assert_eq!(entity.entity_type, "team");
/// assert_eq!(entity.id, "engineering");
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The string doesn't contain exactly one colon
/// - The type or id portions are empty
/// - The type or id don't match the required format
pub fn parse_entity(s: &str) -> Result<AuthZENEntity, EntityError> {
    let parts: Vec<&str> = s.split(':').collect();

    if parts.len() != 2 {
        return Err(EntityError::InvalidFormat(s.to_string()));
    }

    let entity_type = parts[0].to_string();
    let id = parts[1].to_string();

    AuthZENEntity::new(entity_type, id)
}

/// Formats an AuthZEN entity into an InferaDB type:id string
///
/// # Examples
///
/// ```
/// # use infera_api::adapters::authzen::{format_entity, AuthZENEntity};
/// let entity = AuthZENEntity {
///     entity_type: "user".to_string(),
///     id: "alice".to_string(),
/// };
/// assert_eq!(format_entity(&entity), "user:alice");
/// ```
pub fn format_entity(entity: &AuthZENEntity) -> String {
    format!("{}:{}", entity.entity_type, entity.id)
}

/// AuthZEN subject representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthZENSubject {
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
}

/// AuthZEN resource representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthZENResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
}

/// AuthZEN action representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthZENAction {
    pub name: String,
}

/// AuthZEN evaluation request matching the AuthZEN specification
///
/// Example:
/// ```json
/// {
///   "subject": {"type": "user", "id": "alice"},
///   "action": {"name": "view"},
///   "resource": {"type": "document", "id": "readme"}
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENEvaluationRequest {
    pub subject: AuthZENSubject,
    pub action: AuthZENAction,
    pub resource: AuthZENResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// AuthZEN evaluation response matching the AuthZEN specification
///
/// Example:
/// ```json
/// {
///   "decision": true
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthZENEvaluationResponse {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Converts an AuthZEN evaluation request to InferaDB's native format
///
/// Maps:
/// - subject.type:subject.id -> "type:id"
/// - action.name -> permission (relation name)
/// - resource.type:resource.id -> "type:id"
pub fn convert_authzen_request_to_native(
    req: &AuthZENEvaluationRequest,
) -> Result<(String, String, String), EntityError> {
    let subject = format!("{}:{}", req.subject.subject_type, req.subject.id);
    let resource = format!("{}:{}", req.resource.resource_type, req.resource.id);
    let permission = req.action.name.clone();

    // Validate the generated strings
    parse_entity(&subject)?;
    parse_entity(&resource)?;

    Ok((subject, resource, permission))
}

/// Converts a native InferaDB decision to AuthZEN format
pub fn convert_native_decision_to_authzen(decision: bool) -> AuthZENEvaluationResponse {
    AuthZENEvaluationResponse {
        decision,
        context: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_entity_valid() {
        let entity = parse_entity("user:alice").unwrap();
        assert_eq!(entity.entity_type, "user");
        assert_eq!(entity.id, "alice");

        let entity = parse_entity("team:engineering").unwrap();
        assert_eq!(entity.entity_type, "team");
        assert_eq!(entity.id, "engineering");

        let entity = parse_entity("doc:design-doc").unwrap();
        assert_eq!(entity.entity_type, "doc");
        assert_eq!(entity.id, "design-doc");

        let entity = parse_entity("_private:test_123").unwrap();
        assert_eq!(entity.entity_type, "_private");
        assert_eq!(entity.id, "test_123");
    }

    #[test]
    fn test_parse_entity_invalid_format() {
        assert_eq!(
            parse_entity("no-colon"),
            Err(EntityError::InvalidFormat("no-colon".to_string()))
        );

        assert_eq!(
            parse_entity("too:many:colons"),
            Err(EntityError::InvalidFormat("too:many:colons".to_string()))
        );

        assert_eq!(
            parse_entity(""),
            Err(EntityError::InvalidFormat("".to_string()))
        );
    }

    #[test]
    fn test_parse_entity_empty_parts() {
        assert_eq!(parse_entity(":id"), Err(EntityError::EmptyType));
        assert_eq!(parse_entity("type:"), Err(EntityError::EmptyId));
    }

    #[test]
    fn test_parse_entity_invalid_type() {
        // Type can't start with digit
        assert_eq!(
            parse_entity("9user:alice"),
            Err(EntityError::InvalidType("9user".to_string()))
        );

        // Type can't contain uppercase
        assert_eq!(
            parse_entity("User:alice"),
            Err(EntityError::InvalidType("User".to_string()))
        );

        // Type can't contain special characters
        assert_eq!(
            parse_entity("user-type:alice"),
            Err(EntityError::InvalidType("user-type".to_string()))
        );
    }

    #[test]
    fn test_parse_entity_invalid_id() {
        // ID can't contain uppercase
        assert_eq!(
            parse_entity("user:Alice"),
            Err(EntityError::InvalidId("Alice".to_string()))
        );

        // ID can't contain special characters (except - and _)
        assert_eq!(
            parse_entity("user:alice@example"),
            Err(EntityError::InvalidId("alice@example".to_string()))
        );

        assert_eq!(
            parse_entity("user:alice.smith"),
            Err(EntityError::InvalidId("alice.smith".to_string()))
        );
    }

    #[test]
    fn test_format_entity() {
        let entity = AuthZENEntity {
            entity_type: "user".to_string(),
            id: "alice".to_string(),
        };
        assert_eq!(format_entity(&entity), "user:alice");

        let entity = AuthZENEntity {
            entity_type: "team".to_string(),
            id: "engineering".to_string(),
        };
        assert_eq!(format_entity(&entity), "team:engineering");

        let entity = AuthZENEntity {
            entity_type: "doc".to_string(),
            id: "design-doc".to_string(),
        };
        assert_eq!(format_entity(&entity), "doc:design-doc");
    }

    #[test]
    fn test_parse_and_format_roundtrip() {
        let test_cases = vec![
            "user:alice",
            "team:engineering",
            "doc:design-doc",
            "_private:test_123",
            "resource:a-b-c",
        ];

        for input in test_cases {
            let entity = parse_entity(input).unwrap();
            let output = format_entity(&entity);
            assert_eq!(input, output, "Roundtrip failed for: {}", input);
        }
    }

    #[test]
    fn test_authzen_entity_new_valid() {
        let entity = AuthZENEntity::new("user".to_string(), "alice".to_string()).unwrap();
        assert_eq!(entity.entity_type, "user");
        assert_eq!(entity.id, "alice");
    }

    #[test]
    fn test_authzen_entity_new_invalid() {
        assert_eq!(
            AuthZENEntity::new("9user".to_string(), "alice".to_string()),
            Err(EntityError::InvalidType("9user".to_string()))
        );

        assert_eq!(
            AuthZENEntity::new("user".to_string(), "Alice".to_string()),
            Err(EntityError::InvalidId("Alice".to_string()))
        );

        assert_eq!(
            AuthZENEntity::new("".to_string(), "alice".to_string()),
            Err(EntityError::EmptyType)
        );

        assert_eq!(
            AuthZENEntity::new("user".to_string(), "".to_string()),
            Err(EntityError::EmptyId)
        );
    }

    #[test]
    fn test_convert_authzen_request_to_native() {
        let req = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let (subject, resource, permission) = convert_authzen_request_to_native(&req).unwrap();
        assert_eq!(subject, "user:alice");
        assert_eq!(resource, "document:readme");
        assert_eq!(permission, "view");
    }

    #[test]
    fn test_convert_authzen_request_invalid() {
        let req = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "User".to_string(), // Invalid: uppercase
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        assert!(convert_authzen_request_to_native(&req).is_err());
    }

    #[test]
    fn test_convert_native_decision_to_authzen() {
        let response = convert_native_decision_to_authzen(true);
        assert!(response.decision);
        assert!(response.context.is_none());

        let response = convert_native_decision_to_authzen(false);
        assert!(!response.decision);
        assert!(response.context.is_none());
    }

    #[test]
    fn test_validate_type() {
        // Valid types
        assert!(validate_type("user").is_ok());
        assert!(validate_type("team").is_ok());
        assert!(validate_type("_private").is_ok());
        assert!(validate_type("user_type").is_ok());
        assert!(validate_type("type123").is_ok());

        // Invalid types
        assert_eq!(validate_type(""), Err(EntityError::EmptyType));
        assert!(validate_type("User").is_err()); // Uppercase
        assert!(validate_type("9user").is_err()); // Starts with digit
        assert!(validate_type("user-type").is_err()); // Contains hyphen
        assert!(validate_type("user.type").is_err()); // Contains dot
    }

    #[test]
    fn test_validate_id() {
        // Valid IDs
        assert!(validate_id("alice").is_ok());
        assert!(validate_id("alice-bob").is_ok());
        assert!(validate_id("alice_bob").is_ok());
        assert!(validate_id("123").is_ok());
        assert!(validate_id("test-123_abc").is_ok());

        // Invalid IDs
        assert_eq!(validate_id(""), Err(EntityError::EmptyId));
        assert!(validate_id("Alice").is_err()); // Uppercase
        assert!(validate_id("alice@example").is_err()); // Contains @
        assert!(validate_id("alice.smith").is_err()); // Contains dot
        assert!(validate_id("alice bob").is_err()); // Contains space
    }

    #[test]
    fn test_authzen_entity_serialization() {
        let entity = AuthZENEntity {
            entity_type: "user".to_string(),
            id: "alice".to_string(),
        };

        let json = serde_json::to_string(&entity).unwrap();
        assert_eq!(json, r#"{"type":"user","id":"alice"}"#);

        let deserialized: AuthZENEntity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, entity);
    }

    #[test]
    fn test_authzen_evaluation_request_serialization() {
        let req = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            context: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: AuthZENEvaluationRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.subject.subject_type, "user");
        assert_eq!(deserialized.subject.id, "alice");
        assert_eq!(deserialized.action.name, "view");
        assert_eq!(deserialized.resource.resource_type, "document");
        assert_eq!(deserialized.resource.id, "readme");
    }

    #[test]
    fn test_authzen_evaluation_response_serialization() {
        let response = AuthZENEvaluationResponse {
            decision: true,
            context: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"decision":true}"#);

        let deserialized: AuthZENEvaluationResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.decision);
        assert!(deserialized.context.is_none());
    }
}
