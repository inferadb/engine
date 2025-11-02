//! Request validation for AuthZEN endpoints
//!
//! This module provides centralized validation logic for AuthZEN protocol requests.
//! All validation functions return detailed error messages to help clients understand
//! what went wrong.

use crate::adapters::authzen::{
    AuthZENAction, AuthZENEntity, AuthZENEvaluationRequest, AuthZENResource, AuthZENSubject,
};
use crate::handlers::authzen::search::{
    AuthZENResourceSearchRequest, AuthZENSubjectSearchRequest,
};
use crate::ApiError;

/// Validates an AuthZEN entity (subject or resource)
///
/// Checks that:
/// - Type is non-empty
/// - ID is non-empty
///
/// # Example
/// ```
/// use infera_api::adapters::authzen::AuthZENEntity;
/// use infera_api::validation::validate_authzen_entity;
///
/// let entity = AuthZENEntity {
///     entity_type: "user".to_string(),
///     id: "alice".to_string(),
/// };
/// assert!(validate_authzen_entity(&entity, "subject").is_ok());
///
/// let invalid = AuthZENEntity {
///     entity_type: "".to_string(),
///     id: "alice".to_string(),
/// };
/// assert!(validate_authzen_entity(&invalid, "subject").is_err());
/// ```
pub fn validate_authzen_entity(entity: &AuthZENEntity, entity_kind: &str) -> Result<(), ApiError> {
    if entity.entity_type.is_empty() {
        return Err(ApiError::InvalidRequest(format!(
            "{} type cannot be empty",
            entity_kind
        )));
    }
    if entity.id.is_empty() {
        return Err(ApiError::InvalidRequest(format!(
            "{} id cannot be empty",
            entity_kind
        )));
    }
    Ok(())
}

/// Validates an AuthZEN subject
///
/// Checks that:
/// - Subject type is non-empty
/// - Subject id is non-empty
pub fn validate_authzen_subject(subject: &AuthZENSubject) -> Result<(), ApiError> {
    if subject.subject_type.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Subject type cannot be empty".to_string(),
        ));
    }
    if subject.id.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Subject id cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// Validates an AuthZEN resource
///
/// Checks that:
/// - Resource type is non-empty
/// - Resource id is non-empty
pub fn validate_authzen_resource(resource: &AuthZENResource) -> Result<(), ApiError> {
    if resource.resource_type.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Resource type cannot be empty".to_string(),
        ));
    }
    if resource.id.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Resource id cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// Validates an AuthZEN action
///
/// Checks that:
/// - Action name is non-empty
pub fn validate_authzen_action(action: &AuthZENAction) -> Result<(), ApiError> {
    if action.name.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Action name cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// Validates an AuthZEN evaluation request
///
/// Checks that all required fields are present and valid:
/// - Subject (type and id)
/// - Resource (type and id)
/// - Action (name)
///
/// # Example
/// ```
/// use infera_api::adapters::authzen::{
///     AuthZENSubject, AuthZENResource, AuthZENAction, AuthZENEvaluationRequest,
/// };
/// use infera_api::validation::validate_authzen_evaluation_request;
///
/// let request = AuthZENEvaluationRequest {
///     subject: AuthZENSubject {
///         subject_type: "user".to_string(),
///         id: "alice".to_string(),
///     },
///     resource: AuthZENResource {
///         resource_type: "document".to_string(),
///         id: "readme".to_string(),
///     },
///     action: AuthZENAction {
///         name: "view".to_string(),
///     },
///     context: None,
/// };
/// assert!(validate_authzen_evaluation_request(&request).is_ok());
/// ```
pub fn validate_authzen_evaluation_request(
    request: &AuthZENEvaluationRequest,
) -> Result<(), ApiError> {
    validate_authzen_subject(&request.subject)?;
    validate_authzen_resource(&request.resource)?;
    validate_authzen_action(&request.action)?;
    Ok(())
}

/// Validates an AuthZEN resource search request
///
/// Checks that all required fields are present and valid:
/// - Subject (type and id)
/// - Action (name)
/// - Resource type is non-empty
///
/// # Example
/// ```
/// use infera_api::adapters::authzen::{AuthZENSubject, AuthZENAction};
/// use infera_api::handlers::authzen::search::AuthZENResourceSearchRequest;
/// use infera_api::validation::validate_authzen_resource_search_request;
///
/// let request = AuthZENResourceSearchRequest {
///     subject: AuthZENSubject {
///         subject_type: "user".to_string(),
///         id: "alice".to_string(),
///     },
///     action: AuthZENAction {
///         name: "view".to_string(),
///     },
///     resource_type: "document".to_string(),
///     limit: None,
///     cursor: None,
/// };
/// assert!(validate_authzen_resource_search_request(&request).is_ok());
/// ```
pub fn validate_authzen_resource_search_request(
    request: &AuthZENResourceSearchRequest,
) -> Result<(), ApiError> {
    validate_authzen_subject(&request.subject)?;
    validate_authzen_action(&request.action)?;

    if request.resource_type.is_empty() {
        return Err(ApiError::InvalidRequest(
            "Resource type cannot be empty".to_string(),
        ));
    }

    Ok(())
}

/// Validates an AuthZEN subject search request
///
/// Checks that all required fields are present and valid:
/// - Resource (type and id)
/// - Action (name)
///
/// # Example
/// ```
/// use infera_api::adapters::authzen::{AuthZENResource, AuthZENAction};
/// use infera_api::handlers::authzen::search::AuthZENSubjectSearchRequest;
/// use infera_api::validation::validate_authzen_subject_search_request;
///
/// let request = AuthZENSubjectSearchRequest {
///     resource: AuthZENResource {
///         resource_type: "document".to_string(),
///         id: "readme".to_string(),
///     },
///     action: AuthZENAction {
///         name: "view".to_string(),
///     },
///     subject_type: None,
///     limit: None,
///     cursor: None,
/// };
/// assert!(validate_authzen_subject_search_request(&request).is_ok());
/// ```
pub fn validate_authzen_subject_search_request(
    request: &AuthZENSubjectSearchRequest,
) -> Result<(), ApiError> {
    validate_authzen_resource(&request.resource)?;
    validate_authzen_action(&request.action)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Entity validation tests

    #[test]
    fn test_validate_entity_valid() {
        let entity = AuthZENEntity {
            entity_type: "user".to_string(),
            id: "alice".to_string(),
        };
        assert!(validate_authzen_entity(&entity, "subject").is_ok());
    }

    #[test]
    fn test_validate_entity_empty_type() {
        let entity = AuthZENEntity {
            entity_type: "".to_string(),
            id: "alice".to_string(),
        };
        let result = validate_authzen_entity(&entity, "subject");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("subject type cannot be empty"));
    }

    #[test]
    fn test_validate_entity_empty_id() {
        let entity = AuthZENEntity {
            entity_type: "user".to_string(),
            id: "".to_string(),
        };
        let result = validate_authzen_entity(&entity, "resource");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("resource id cannot be empty"));
    }

    // Subject validation tests

    #[test]
    fn test_validate_subject_valid() {
        let subject = AuthZENSubject {
            subject_type: "user".to_string(),
            id: "alice".to_string(),
        };
        assert!(validate_authzen_subject(&subject).is_ok());
    }

    #[test]
    fn test_validate_subject_empty_type() {
        let subject = AuthZENSubject {
            subject_type: "".to_string(),
            id: "alice".to_string(),
        };
        let result = validate_authzen_subject(&subject);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Subject type cannot be empty"));
    }

    #[test]
    fn test_validate_subject_empty_id() {
        let subject = AuthZENSubject {
            subject_type: "user".to_string(),
            id: "".to_string(),
        };
        let result = validate_authzen_subject(&subject);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Subject id cannot be empty"));
    }

    // Resource validation tests

    #[test]
    fn test_validate_resource_valid() {
        let resource = AuthZENResource {
            resource_type: "document".to_string(),
            id: "readme".to_string(),
        };
        assert!(validate_authzen_resource(&resource).is_ok());
    }

    #[test]
    fn test_validate_resource_empty_type() {
        let resource = AuthZENResource {
            resource_type: "".to_string(),
            id: "readme".to_string(),
        };
        let result = validate_authzen_resource(&resource);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Resource type cannot be empty"));
    }

    #[test]
    fn test_validate_resource_empty_id() {
        let resource = AuthZENResource {
            resource_type: "document".to_string(),
            id: "".to_string(),
        };
        let result = validate_authzen_resource(&resource);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Resource id cannot be empty"));
    }

    // Action validation tests

    #[test]
    fn test_validate_action_valid() {
        let action = AuthZENAction {
            name: "view".to_string(),
        };
        assert!(validate_authzen_action(&action).is_ok());
    }

    #[test]
    fn test_validate_action_empty_name() {
        let action = AuthZENAction {
            name: "".to_string(),
        };
        let result = validate_authzen_action(&action);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Action name cannot be empty"));
    }

    // Evaluation request validation tests

    #[test]
    fn test_validate_evaluation_request_valid() {
        let request = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            context: None,
        };
        assert!(validate_authzen_evaluation_request(&request).is_ok());
    }

    #[test]
    fn test_validate_evaluation_request_invalid_subject() {
        let request = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "".to_string(),
                id: "alice".to_string(),
            },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            context: None,
        };
        assert!(validate_authzen_evaluation_request(&request).is_err());
    }

    #[test]
    fn test_validate_evaluation_request_invalid_resource() {
        let request = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            context: None,
        };
        assert!(validate_authzen_evaluation_request(&request).is_err());
    }

    #[test]
    fn test_validate_evaluation_request_invalid_action() {
        let request = AuthZENEvaluationRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction {
                name: "".to_string(),
            },
            context: None,
        };
        assert!(validate_authzen_evaluation_request(&request).is_err());
    }

    // Resource search request validation tests

    #[test]
    fn test_validate_resource_search_request_valid() {
        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };
        assert!(validate_authzen_resource_search_request(&request).is_ok());
    }

    #[test]
    fn test_validate_resource_search_request_invalid_subject() {
        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };
        assert!(validate_authzen_resource_search_request(&request).is_err());
    }

    #[test]
    fn test_validate_resource_search_request_invalid_action() {
        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "".to_string(),
            },
            resource_type: "document".to_string(),
            limit: None,
            cursor: None,
        };
        assert!(validate_authzen_resource_search_request(&request).is_err());
    }

    #[test]
    fn test_validate_resource_search_request_empty_resource_type() {
        let request = AuthZENResourceSearchRequest {
            subject: AuthZENSubject {
                subject_type: "user".to_string(),
                id: "alice".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            resource_type: "".to_string(),
            limit: None,
            cursor: None,
        };
        let result = validate_authzen_resource_search_request(&request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Resource type cannot be empty"));
    }

    // Subject search request validation tests

    #[test]
    fn test_validate_subject_search_request_valid() {
        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            subject_type: None,
            limit: None,
            cursor: None,
        };
        assert!(validate_authzen_subject_search_request(&request).is_ok());
    }

    #[test]
    fn test_validate_subject_search_request_invalid_resource() {
        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            subject_type: None,
            limit: None,
            cursor: None,
        };
        assert!(validate_authzen_subject_search_request(&request).is_err());
    }

    #[test]
    fn test_validate_subject_search_request_invalid_action() {
        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction {
                name: "".to_string(),
            },
            subject_type: None,
            limit: None,
            cursor: None,
        };
        assert!(validate_authzen_subject_search_request(&request).is_err());
    }

    #[test]
    fn test_validate_subject_search_request_with_subject_type_filter() {
        let request = AuthZENSubjectSearchRequest {
            resource: AuthZENResource {
                resource_type: "document".to_string(),
                id: "readme".to_string(),
            },
            action: AuthZENAction {
                name: "view".to_string(),
            },
            subject_type: Some("user".to_string()),
            limit: Some(10),
            cursor: Some("token".to_string()),
        };
        assert!(validate_authzen_subject_search_request(&request).is_ok());
    }
}
