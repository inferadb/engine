//! IPL Schema Validation Framework
//!
//! This module provides comprehensive validation for IPL schemas, including:
//! - Type checking: Validates that all relation and type references exist
//! - Conflict detection: Finds conflicts between permit and forbid rules
//! - Coverage analysis: Identifies unused relations and suggests improvements
//!
//! # Usage
//!
//! ```rust,no_run
//! use inferadb_core::ipl::validation::Validator;
//! use inferadb_core::ipl::parse_schema;
//!
//! let source = r#"
//!     type document {
//!         relation owner
//!         relation viewer: owner
//!     }
//! "#;
//!
//! let schema = parse_schema(source).unwrap();
//! let validator = Validator::new(&schema);
//! let results = validator.validate();
//!
//! if results.has_errors() {
//!     for error in results.errors() {
//!         eprintln!("{}", error);
//!     }
//! }
//! ```

pub mod conflict_detector;
pub mod coverage_analyzer;
pub mod error;
pub mod type_checker;

use conflict_detector::ConflictDetector;
use coverage_analyzer::CoverageAnalyzer;
pub use error::{
    ConflictError, CoverageWarning, ErrorLocation, Severity, TypeCheckError, ValidationError,
    ValidationErrorKind,
};
use type_checker::TypeChecker;

use crate::ipl::ast::Schema;

/// Validation results containing all errors and warnings
#[derive(Debug, Clone)]
pub struct ValidationResults {
    errors: Vec<ValidationError>,
}

impl ValidationResults {
    /// Create a new validation results object
    pub fn new(errors: Vec<ValidationError>) -> Self {
        Self { errors }
    }

    /// Check if there are any blocking errors
    pub fn has_errors(&self) -> bool {
        self.errors.iter().any(|e| e.severity() == Severity::Error)
    }

    /// Check if there are any warnings
    pub fn has_warnings(&self) -> bool {
        self.errors.iter().any(|e| e.severity() == Severity::Warning)
    }

    /// Get all validation errors (includes warnings and info)
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    /// Get only errors (severity Error)
    pub fn error_messages(&self) -> Vec<&ValidationError> {
        self.errors.iter().filter(|e| e.severity() == Severity::Error).collect()
    }

    /// Get only warnings (severity Warning)
    pub fn warning_messages(&self) -> Vec<&ValidationError> {
        self.errors.iter().filter(|e| e.severity() == Severity::Warning).collect()
    }

    /// Get only info messages (severity Info)
    pub fn info_messages(&self) -> Vec<&ValidationError> {
        self.errors.iter().filter(|e| e.severity() == Severity::Info).collect()
    }

    /// Get the total count of all validation messages
    pub fn total_count(&self) -> usize {
        self.errors.len()
    }

    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        !self.has_errors()
    }

    /// Get a summary of validation results
    pub fn summary(&self) -> String {
        let errors = self.error_messages().len();
        let warnings = self.warning_messages().len();
        let info = self.info_messages().len();

        if errors > 0 {
            format!(
                "Validation failed: {} error(s), {} warning(s), {} info",
                errors, warnings, info
            )
        } else if warnings > 0 {
            format!("Validation passed with warnings: {} warning(s), {} info", warnings, info)
        } else {
            format!("Validation passed: {} info message(s)", info)
        }
    }
}

/// Main validator for IPL schemas
///
/// Coordinates type checking, conflict detection, and coverage analysis
/// to provide comprehensive validation of IPL schemas.
pub struct Validator<'a> {
    schema: &'a Schema,
}

impl<'a> Validator<'a> {
    /// Create a new validator for the given schema
    pub fn new(schema: &'a Schema) -> Self {
        Self { schema }
    }

    /// Run all validation checks and return results
    ///
    /// This runs:
    /// 1. Type checking - validates references exist
    /// 2. Conflict detection - finds permit/forbid conflicts and unreachable relations
    /// 3. Coverage analysis - identifies unused relations and suggests tests
    pub fn validate(&self) -> ValidationResults {
        let mut all_errors = Vec::new();

        // Run type checking
        let type_checker = TypeChecker::new(self.schema);
        all_errors.extend(type_checker.check());

        // Run conflict detection
        let conflict_detector = ConflictDetector::new(self.schema);
        all_errors.extend(conflict_detector.detect());

        // Run coverage analysis
        let coverage_analyzer = CoverageAnalyzer::new(self.schema);
        all_errors.extend(coverage_analyzer.analyze());

        ValidationResults::new(all_errors)
    }

    /// Run only type checking
    pub fn type_check(&self) -> ValidationResults {
        let type_checker = TypeChecker::new(self.schema);
        ValidationResults::new(type_checker.check())
    }

    /// Run only conflict detection
    pub fn detect_conflicts(&self) -> ValidationResults {
        let conflict_detector = ConflictDetector::new(self.schema);
        ValidationResults::new(conflict_detector.detect())
    }

    /// Run only coverage analysis
    pub fn analyze_coverage(&self) -> ValidationResults {
        let coverage_analyzer = CoverageAnalyzer::new(self.schema);
        ValidationResults::new(coverage_analyzer.analyze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipl::ast::{ForbidDef, RelationDef, RelationExpr, Schema, TypeDef};

    #[test]
    fn test_validator_with_valid_schema() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
            ],
        )]);

        let validator = Validator::new(&schema);
        let results = validator.validate();

        // May have info messages (test suggestions) but no errors
        assert!(results.is_valid());
        assert!(!results.has_errors());
    }

    #[test]
    fn test_validator_with_type_error() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::RelationRef { relation: "nonexistent".to_string() }),
            )],
        )]);

        let validator = Validator::new(&schema);
        let results = validator.validate();

        assert!(!results.is_valid());
        assert!(results.has_errors());
        assert!(!results.error_messages().is_empty());
    }

    #[test]
    fn test_validator_with_conflict() {
        let schema = Schema::new(vec![TypeDef::new_with_forbids(
            "document".to_string(),
            vec![RelationDef::new("viewer".to_string(), None)],
            vec![ForbidDef::new("viewer".to_string(), None)],
        )]);

        let validator = Validator::new(&schema);
        let results = validator.validate();

        assert!(!results.is_valid());
        assert!(results.has_errors());
    }

    #[test]
    fn test_validation_results_summary() {
        let errors = vec![
            ValidationError::new(
                ErrorLocation::type_level("document".to_string()),
                ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelation {
                    referenced: "test".to_string(),
                }),
                "Error message".to_string(),
                None,
            ),
            ValidationError::new(
                ErrorLocation::type_level("document".to_string()),
                ValidationErrorKind::Conflict(ConflictError::UnreachableRelation {
                    relation: "test".to_string(),
                    reason: "Never used".to_string(),
                }),
                "Warning message".to_string(),
                None,
            ),
        ];

        let results = ValidationResults::new(errors);
        let summary = results.summary();

        assert!(summary.contains("1 error"));
        assert!(summary.contains("1 warning"));
    }

    #[test]
    fn test_type_check_only() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::RelationRef { relation: "nonexistent".to_string() }),
            )],
        )]);

        let validator = Validator::new(&schema);
        let results = validator.type_check();

        assert!(results.has_errors());
    }

    #[test]
    fn test_detect_conflicts_only() {
        let schema = Schema::new(vec![TypeDef::new_with_forbids(
            "document".to_string(),
            vec![RelationDef::new("viewer".to_string(), None)],
            vec![ForbidDef::new("viewer".to_string(), None)],
        )]);

        let validator = Validator::new(&schema);
        let results = validator.detect_conflicts();

        assert!(results.has_errors());
    }

    #[test]
    fn test_analyze_coverage_only() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new(
                    "unused".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
            ],
        )]);

        let validator = Validator::new(&schema);
        let results = validator.analyze_coverage();

        // Should have coverage warnings but they're not errors
        assert!(results.total_count() > 0);
    }
}
