//! Request validation utilities shared across services

use inferadb_types::{
    DeleteFilter, EvaluateRequest, ListRelationshipsRequest, ListResourcesRequest,
    ListSubjectsRequest, Relationship,
};

use crate::ApiError;

/// Validates an evaluation request
///
/// # Errors
/// Returns `ApiError::InvalidRequest` if:
/// - Subject is empty
/// - Resource is empty
/// - Permission is empty
/// - Subject/resource format is invalid (not "type:id")
pub fn validate_evaluate_request(request: &EvaluateRequest) -> Result<(), ApiError> {
    if request.subject.is_empty() {
        return Err(ApiError::InvalidRequest("Subject cannot be empty".to_string()));
    }
    if request.resource.is_empty() {
        return Err(ApiError::InvalidRequest("Resource cannot be empty".to_string()));
    }
    if request.permission.is_empty() {
        return Err(ApiError::InvalidRequest("Permission cannot be empty".to_string()));
    }

    // Validate entity format
    validate_entity_format(&request.subject, "subject")?;
    validate_entity_format(&request.resource, "resource")?;

    Ok(())
}

/// Validates a list resources request
///
/// # Errors
/// Returns `ApiError::InvalidRequest` if:
/// - Subject is empty
/// - Resource type is empty
/// - Permission is empty
/// - Subject format is invalid
pub fn validate_list_resources_request(request: &ListResourcesRequest) -> Result<(), ApiError> {
    if request.subject.is_empty() {
        return Err(ApiError::InvalidRequest("Subject cannot be empty".to_string()));
    }
    if request.resource_type.is_empty() {
        return Err(ApiError::InvalidRequest("Resource type cannot be empty".to_string()));
    }
    if request.permission.is_empty() {
        return Err(ApiError::InvalidRequest("Permission cannot be empty".to_string()));
    }

    // Validate subject format
    validate_entity_format(&request.subject, "subject")?;

    Ok(())
}

/// Validates a list subjects request
///
/// # Errors
/// Returns `ApiError::InvalidRequest` if:
/// - Resource is empty
/// - Relation is empty
/// - Resource format is invalid
pub fn validate_list_subjects_request(request: &ListSubjectsRequest) -> Result<(), ApiError> {
    if request.resource.is_empty() {
        return Err(ApiError::InvalidRequest("Resource cannot be empty".to_string()));
    }
    if request.relation.is_empty() {
        return Err(ApiError::InvalidRequest("Relation cannot be empty".to_string()));
    }

    // Validate resource format
    validate_entity_format(&request.resource, "resource")?;

    Ok(())
}

/// Validates a list relationships request
///
/// # Errors
/// Returns `ApiError::InvalidRequest` if any filter fields have invalid format
pub fn validate_list_relationships_request(
    request: &ListRelationshipsRequest,
) -> Result<(), ApiError> {
    // All filters are optional, but if provided must be valid
    if let Some(ref resource) = request.resource {
        if !resource.is_empty() {
            validate_entity_format(resource, "resource")?;
        }
    }
    if let Some(ref subject) = request.subject {
        if !subject.is_empty() {
            validate_entity_format(subject, "subject")?;
        }
    }

    Ok(())
}

/// Validates a relationship
///
/// # Errors
/// Returns `ApiError::InvalidRequest` if:
/// - Resource is empty or invalid format
/// - Relation is empty
/// - Subject is empty or invalid format
/// - Wildcard is used in wrong position
pub fn validate_relationship(relationship: &Relationship) -> Result<(), ApiError> {
    if relationship.resource.is_empty() {
        return Err(ApiError::InvalidRequest("Resource cannot be empty".to_string()));
    }
    if relationship.relation.is_empty() {
        return Err(ApiError::InvalidRequest("Relation cannot be empty".to_string()));
    }
    if relationship.subject.is_empty() {
        return Err(ApiError::InvalidRequest("Subject cannot be empty".to_string()));
    }

    // Validate formats
    validate_entity_format(&relationship.resource, "resource")?;

    // Subject can be wildcard (e.g., "user:*") or regular entity
    if !relationship.subject.ends_with(":*") {
        validate_entity_format(&relationship.subject, "subject")?;
    } else {
        // Validate wildcard format
        validate_wildcard_subject(&relationship.subject)?;
    }

    Ok(())
}

/// Validates a delete filter
///
/// # Errors
/// Returns `ApiError::InvalidRequest` if filter fields have invalid format
pub fn validate_delete_filter(filter: &DeleteFilter) -> Result<(), ApiError> {
    // At least one field must be specified
    if filter.resource.is_none() && filter.relation.is_none() && filter.subject.is_none() {
        return Err(ApiError::InvalidRequest(
            "At least one filter field must be specified".to_string(),
        ));
    }

    // Validate non-empty filters
    if let Some(ref resource) = filter.resource {
        if !resource.is_empty() {
            validate_entity_format(resource, "resource")?;
        }
    }
    if let Some(ref subject) = filter.subject {
        if !subject.is_empty() {
            validate_entity_format(subject, "subject")?;
        }
    }

    Ok(())
}

/// Validates entity format (must be "type:id")
///
/// # Errors
/// Returns `ApiError::InvalidRequest` if format is invalid
fn validate_entity_format(entity: &str, field_name: &str) -> Result<(), ApiError> {
    if !entity.contains(':') {
        return Err(ApiError::InvalidRequest(format!(
            "{} must be in format 'type:id', got: '{}'",
            field_name, entity
        )));
    }

    let parts: Vec<&str> = entity.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(ApiError::InvalidRequest(format!(
            "{} must be in format 'type:id', got: '{}'",
            field_name, entity
        )));
    }

    let (entity_type, id) = (parts[0], parts[1]);

    if entity_type.is_empty() {
        return Err(ApiError::InvalidRequest(format!(
            "{} type cannot be empty in '{}'",
            field_name, entity
        )));
    }

    if id.is_empty() {
        return Err(ApiError::InvalidRequest(format!(
            "{} id cannot be empty in '{}'",
            field_name, entity
        )));
    }

    // Entity type must be lowercase alphanumeric with underscores
    if !entity_type.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err(ApiError::InvalidRequest(format!(
            "{} type must be lowercase alphanumeric with underscores, got: '{}'",
            field_name, entity_type
        )));
    }

    Ok(())
}

/// Validates wildcard subject format (must be "type:*")
fn validate_wildcard_subject(subject: &str) -> Result<(), ApiError> {
    if !subject.ends_with(":*") {
        return Err(ApiError::InvalidRequest(format!(
            "Wildcard subject must end with ':*', got: '{}'",
            subject
        )));
    }

    let entity_type = subject.trim_end_matches(":*");
    if entity_type.is_empty() {
        return Err(ApiError::InvalidRequest("Wildcard subject type cannot be empty".to_string()));
    }

    // Entity type must be lowercase alphanumeric with underscores
    if !entity_type.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err(ApiError::InvalidRequest(format!(
            "Wildcard subject type must be lowercase alphanumeric with underscores, got: '{}'",
            entity_type
        )));
    }

    Ok(())
}

/// Parses an entity string into (type, id)
///
/// # Errors
/// Returns error if entity format is invalid
pub fn parse_entity(entity: &str) -> Result<(String, String), ApiError> {
    validate_entity_format(entity, "entity")?;

    let parts: Vec<&str> = entity.splitn(2, ':').collect();
    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_entity_format() {
        // Valid formats
        assert!(validate_entity_format("user:alice", "test").is_ok());
        assert!(validate_entity_format("document:readme", "test").is_ok());
        assert!(validate_entity_format("org_unit:engineering", "test").is_ok());

        // Invalid formats
        assert!(validate_entity_format("", "test").is_err());
        assert!(validate_entity_format("user", "test").is_err());
        assert!(validate_entity_format(":alice", "test").is_err());
        assert!(validate_entity_format("user:", "test").is_err());
        assert!(validate_entity_format("User:alice", "test").is_err()); // uppercase
        assert!(validate_entity_format("user-admin:alice", "test").is_err()); // hyphen
    }

    #[test]
    fn test_validate_wildcard_subject() {
        // Valid wildcards
        assert!(validate_wildcard_subject("user:*").is_ok());
        assert!(validate_wildcard_subject("org_unit:*").is_ok());

        // Invalid wildcards
        assert!(validate_wildcard_subject("user:alice").is_err());
        assert!(validate_wildcard_subject(":*").is_err());
        assert!(validate_wildcard_subject("User:*").is_err()); // uppercase
    }

    #[test]
    fn test_parse_entity() {
        let (entity_type, id) = parse_entity("user:alice").unwrap();
        assert_eq!(entity_type, "user");
        assert_eq!(id, "alice");

        let (entity_type, id) = parse_entity("document:readme:v2").unwrap();
        assert_eq!(entity_type, "document");
        assert_eq!(id, "readme:v2"); // ID can contain colons

        assert!(parse_entity("invalid").is_err());
    }

    #[test]
    fn test_validate_evaluate_request() {
        let valid_request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "document:readme".to_string(),
            permission: "view".to_string(),
            context: None,
            trace: None,
        };
        assert!(validate_evaluate_request(&valid_request).is_ok());

        let invalid_request = EvaluateRequest {
            subject: "".to_string(),
            resource: "document:readme".to_string(),
            permission: "view".to_string(),
            context: None,
            trace: None,
        };
        assert!(validate_evaluate_request(&invalid_request).is_err());
    }

    #[test]
    fn test_validate_relationship() {
        let valid = Relationship {
            vault: 0,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert!(validate_relationship(&valid).is_ok());

        let wildcard = Relationship {
            vault: 0,
            resource: "document:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:*".to_string(),
        };
        assert!(validate_relationship(&wildcard).is_ok());

        let invalid = Relationship {
            vault: 0,
            resource: "".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert!(validate_relationship(&invalid).is_err());
    }
}
