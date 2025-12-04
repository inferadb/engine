//! Validation errors for IPL schemas

use std::fmt;

/// A validation error that represents a problem in an IPL schema
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Location in the schema where the error occurred
    pub location: ErrorLocation,
    /// Type of validation error
    pub kind: ValidationErrorKind,
    /// Human-readable error message
    pub message: String,
    /// Optional suggestion for fixing the error
    pub suggestion: Option<String>,
}

/// Location information for a validation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLocation {
    /// Type name where the error occurred
    pub type_name: String,
    /// Optional relation or forbid name
    pub relation_name: Option<String>,
}

/// Category of validation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationErrorKind {
    /// Type checking errors
    TypeCheck(TypeCheckError),
    /// Conflict detection errors
    Conflict(ConflictError),
    /// Coverage analysis warnings
    Coverage(CoverageWarning),
}

/// Type checking error categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeCheckError {
    /// Referenced relation does not exist
    UndefinedRelation { referenced: String },
    /// Referenced type does not exist
    UndefinedType { referenced: String },
    /// Referenced relationship (for computed userset) does not exist
    UndefinedRelationship { referenced: String },
    /// Relation reference in expression has wrong type
    InvalidRelationReference { relation: String, expected_type: String },
    /// Circular dependency detected
    CircularDependency { chain: Vec<String> },
}

/// Conflict detection error categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictError {
    /// Permit and forbid conflict on the same permission
    PermitForbidConflict { permission: String, forbid_name: String },
    /// Unreachable relation (dead code)
    UnreachableRelation { relation: String, reason: String },
    /// Ambiguous permission evaluation
    AmbiguousPermission { permission: String, paths: Vec<String> },
}

/// Coverage analysis warning categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageWarning {
    /// Unused relation (never referenced)
    UnusedRelation { relation: String },
    /// Permission without any direct or computed path
    UncoveredPermission { permission: String },
    /// Recommended test case
    MissingTestCase { description: String },
}

impl ValidationError {
    /// Create a new validation error
    pub fn new(
        location: ErrorLocation,
        kind: ValidationErrorKind,
        message: String,
        suggestion: Option<String>,
    ) -> Self {
        Self { location, kind, message, suggestion }
    }

    /// Get severity level of this error
    pub fn severity(&self) -> Severity {
        match &self.kind {
            ValidationErrorKind::TypeCheck(_) => Severity::Error,
            ValidationErrorKind::Conflict(c) => match c {
                ConflictError::PermitForbidConflict { .. } => Severity::Error,
                ConflictError::UnreachableRelation { .. } => Severity::Warning,
                ConflictError::AmbiguousPermission { .. } => Severity::Warning,
            },
            ValidationErrorKind::Coverage(_) => Severity::Info,
        }
    }
}

/// Severity level for validation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational message
    Info,
    /// Warning (non-blocking)
    Warning,
    /// Error (blocks deployment)
    Error,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} in type '{}'", self.severity(), self.message, self.location.type_name)?;

        if let Some(relation) = &self.location.relation_name {
            write!(f, ", relation '{}'", relation)?;
        }

        if let Some(suggestion) = &self.suggestion {
            write!(f, "\n  Suggestion: {}", suggestion)?;
        }

        Ok(())
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Error => write!(f, "ERROR"),
        }
    }
}

impl ErrorLocation {
    /// Create a location for a type-level error
    pub fn type_level(type_name: String) -> Self {
        Self { type_name, relation_name: None }
    }

    /// Create a location for a relation-level error
    pub fn relation_level(type_name: String, relation_name: String) -> Self {
        Self { type_name, relation_name: Some(relation_name) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity() {
        let err = ValidationError::new(
            ErrorLocation::type_level("document".to_string()),
            ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelation {
                referenced: "viewer".to_string(),
            }),
            "Undefined relation".to_string(),
            None,
        );

        assert_eq!(err.severity(), Severity::Error);
    }

    #[test]
    fn test_error_display() {
        let err = ValidationError::new(
            ErrorLocation::relation_level("document".to_string(), "viewer".to_string()),
            ValidationErrorKind::Coverage(CoverageWarning::UnusedRelation {
                relation: "viewer".to_string(),
            }),
            "Relation is never used".to_string(),
            Some("Remove unused relation or add it to a permission".to_string()),
        );

        let display = format!("{}", err);
        assert!(display.contains("INFO"));
        assert!(display.contains("document"));
        assert!(display.contains("viewer"));
        assert!(display.contains("Suggestion:"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }
}
