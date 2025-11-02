//! Coverage analyzer for IPL schemas
//!
//! Analyzes schema coverage to find unused relations, uncovered permissions,
//! and suggest test cases.

use std::collections::HashSet;

use super::error::{CoverageWarning, ErrorLocation, ValidationError, ValidationErrorKind};
use crate::ipl::ast::{RelationExpr, Schema, TypeDef};

/// Coverage analyzer finds coverage issues in IPL schemas
pub struct CoverageAnalyzer<'a> {
    schema: &'a Schema,
}

impl<'a> CoverageAnalyzer<'a> {
    /// Create a new coverage analyzer for the given schema
    pub fn new(schema: &'a Schema) -> Self {
        Self { schema }
    }

    /// Run coverage analysis and return all warnings found
    pub fn analyze(&self) -> Vec<ValidationError> {
        let mut warnings = Vec::new();

        for type_def in &self.schema.types {
            warnings.extend(self.analyze_type_coverage(type_def));
        }

        // Generate suggested test cases
        warnings.extend(self.suggest_test_cases());

        warnings
    }

    /// Analyze coverage for a single type definition
    fn analyze_type_coverage(&self, type_def: &TypeDef) -> Vec<ValidationError> {
        let mut warnings = Vec::new();

        // Find unused relations
        warnings.extend(self.find_unused_relations(type_def));

        // Find permissions without any direct path
        warnings.extend(self.find_uncovered_permissions(type_def));

        warnings
    }

    /// Find relations that are never used
    fn find_unused_relations(&self, type_def: &TypeDef) -> Vec<ValidationError> {
        let mut warnings = Vec::new();
        let mut used_relations = HashSet::new();

        // Collect all referenced relations
        for relation in &type_def.relations {
            if let Some(expr) = &relation.expr {
                Self::collect_relation_refs(expr, &mut used_relations);
            }
        }

        // Check forbid expressions too
        for forbid in &type_def.forbids {
            if let Some(expr) = &forbid.expr {
                Self::collect_relation_refs(expr, &mut used_relations);
            }
        }

        // Find relations that are defined but not used
        for relation in &type_def.relations {
            // Skip direct relations (they're used via tuples)
            if relation.is_direct() {
                continue;
            }

            // Check if relation is referenced
            let is_used = used_relations.contains(&relation.name);

            // Check if relation has a matching forbid (means it's used for permission checks)
            let has_forbid = type_def.find_forbid(&relation.name).is_some();

            // If not used and no forbid, it's potentially unused
            if !is_used && !has_forbid {
                warnings.push(ValidationError::new(
                    ErrorLocation::relation_level(type_def.name.clone(), relation.name.clone()),
                    ValidationErrorKind::Coverage(CoverageWarning::UnusedRelation {
                        relation: relation.name.clone(),
                    }),
                    format!(
                        "Relation '{}' may be unused - consider adding it to a permission check",
                        relation.name
                    ),
                    Some("Remove the relation or use it in a permission evaluation".to_string()),
                ));
            }
        }

        warnings
    }

    /// Collect all relation references from an expression
    fn collect_relation_refs(expr: &RelationExpr, refs: &mut HashSet<String>) {
        match expr {
            RelationExpr::RelationRef { relation } => {
                refs.insert(relation.clone());
            },
            RelationExpr::ComputedUserset { relation: _, relationship } => {
                refs.insert(relationship.clone());
            },
            RelationExpr::RelatedObjectUserset { relationship, computed: _ } => {
                refs.insert(relationship.clone());
            },
            RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => {
                for sub_expr in exprs {
                    Self::collect_relation_refs(sub_expr, refs);
                }
            },
            RelationExpr::Exclusion { base, subtract } => {
                Self::collect_relation_refs(base, refs);
                Self::collect_relation_refs(subtract, refs);
            },
            _ => {},
        }
    }

    /// Find permissions that have no direct or computed path
    fn find_uncovered_permissions(&self, type_def: &TypeDef) -> Vec<ValidationError> {
        let mut warnings = Vec::new();

        // Check each relation to see if it has any way to be satisfied
        for relation in &type_def.relations {
            let has_path = match &relation.expr {
                None => true,                     // Direct relation via tuples
                Some(RelationExpr::This) => true, // Direct via this
                Some(expr) => Self::expression_has_path(expr, type_def),
            };

            if !has_path {
                warnings.push(ValidationError::new(
                    ErrorLocation::relation_level(type_def.name.clone(), relation.name.clone()),
                    ValidationErrorKind::Coverage(CoverageWarning::UncoveredPermission {
                        permission: relation.name.clone(),
                    }),
                    format!(
                        "Permission '{}' may be unreachable - no valid path to grant access",
                        relation.name
                    ),
                    Some("Ensure the permission has at least one way to be granted".to_string()),
                ));
            }
        }

        warnings
    }

    /// Check if an expression has at least one path to grant permission
    fn expression_has_path(expr: &RelationExpr, type_def: &TypeDef) -> bool {
        match expr {
            RelationExpr::This => true,
            RelationExpr::RelationRef { relation } => {
                // Check if the referenced relation exists and has a path
                if let Some(rel_def) = type_def.find_relation(relation) {
                    match &rel_def.expr {
                        None => true,
                        Some(RelationExpr::This) => true,
                        Some(sub_expr) => Self::expression_has_path(sub_expr, type_def),
                    }
                } else {
                    false
                }
            },
            RelationExpr::ComputedUserset { .. }
            | RelationExpr::RelatedObjectUserset { .. }
            | RelationExpr::WasmModule { .. } => {
                // These are runtime-evaluated, assume they have paths
                true
            },
            RelationExpr::Union(exprs) => {
                // At least one branch must have a path
                exprs.iter().any(|e| Self::expression_has_path(e, type_def))
            },
            RelationExpr::Intersection(exprs) => {
                // All branches must have paths
                exprs.iter().all(|e| Self::expression_has_path(e, type_def))
            },
            RelationExpr::Exclusion { base, subtract: _ } => {
                // Base must have a path (subtract doesn't matter for reachability)
                Self::expression_has_path(base, type_def)
            },
        }
    }

    /// Suggest test cases based on the schema
    fn suggest_test_cases(&self) -> Vec<ValidationError> {
        let mut warnings = Vec::new();

        for type_def in &self.schema.types {
            // Suggest tests for direct relations
            let direct_relations: Vec<_> =
                type_def.relations.iter().filter(|r| r.is_direct()).collect();

            if !direct_relations.is_empty() {
                warnings.push(ValidationError::new(
                    ErrorLocation::type_level(type_def.name.clone()),
                    ValidationErrorKind::Coverage(CoverageWarning::MissingTestCase {
                        description: format!(
                            "Add tests for direct relations: {}",
                            direct_relations
                                .iter()
                                .map(|r| r.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    }),
                    format!("Consider adding integration tests for type '{}'", type_def.name),
                    Some("Test direct tuple grants for each relation".to_string()),
                ));
            }

            // Suggest tests for computed relations
            let computed_relations: Vec<_> =
                type_def.relations.iter().filter(|r| !r.is_direct() && r.expr.is_some()).collect();

            if !computed_relations.is_empty() {
                warnings.push(ValidationError::new(
                    ErrorLocation::type_level(type_def.name.clone()),
                    ValidationErrorKind::Coverage(CoverageWarning::MissingTestCase {
                        description: format!(
                            "Add tests for computed relations: {}",
                            computed_relations
                                .iter()
                                .map(|r| r.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    }),
                    format!(
                        "Consider adding tests for computed permissions in type '{}'",
                        type_def.name
                    ),
                    Some("Test each permission path through relation expressions".to_string()),
                ));
            }

            // Suggest tests for forbid rules
            if !type_def.forbids.is_empty() {
                warnings.push(ValidationError::new(
                    ErrorLocation::type_level(type_def.name.clone()),
                    ValidationErrorKind::Coverage(CoverageWarning::MissingTestCase {
                        description: format!(
                            "Add tests for forbid rules: {}",
                            type_def
                                .forbids
                                .iter()
                                .map(|f| f.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    }),
                    format!("Consider adding tests for forbid rules in type '{}'", type_def.name),
                    Some("Test that forbid rules correctly deny access".to_string()),
                ));
            }
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipl::ast::{ForbidDef, RelationDef, RelationExpr, Schema, TypeDef};

    #[test]
    fn test_unused_relation_warning() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                // This computed relation is never used
                RelationDef::new(
                    "unused".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
            ],
        )]);

        let analyzer = CoverageAnalyzer::new(&schema);
        let warnings = analyzer.analyze();

        assert!(warnings.iter().any(|w| matches!(
            &w.kind,
            ValidationErrorKind::Coverage(CoverageWarning::UnusedRelation { .. })
        )));
    }

    #[test]
    fn test_no_unused_relation_warning_when_used() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new(
                    "editor".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::RelationRef { relation: "editor".to_string() }),
                ),
            ],
        )]);

        let analyzer = CoverageAnalyzer::new(&schema);
        let warnings = analyzer.analyze();

        // editor is used by viewer, so no unused warning for it
        let unused_warnings: Vec<_> = warnings
            .iter()
            .filter(|w| {
                matches!(
                    &w.kind,
                    ValidationErrorKind::Coverage(CoverageWarning::UnusedRelation {
                        relation
                    }) if relation == "editor"
                )
            })
            .collect();

        assert_eq!(unused_warnings.len(), 0);
    }

    #[test]
    fn test_suggest_test_cases() {
        let schema = Schema::new(vec![TypeDef::new_with_forbids(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
            ],
            vec![ForbidDef::new("blocked".to_string(), None)],
        )]);

        let analyzer = CoverageAnalyzer::new(&schema);
        let warnings = analyzer.analyze();

        // Should suggest test cases for direct relations, computed relations, and forbids
        let test_suggestions: Vec<_> = warnings
            .iter()
            .filter(|w| {
                matches!(
                    &w.kind,
                    ValidationErrorKind::Coverage(CoverageWarning::MissingTestCase { .. })
                )
            })
            .collect();

        assert!(test_suggestions.len() >= 3);
    }

    #[test]
    fn test_uncovered_permission_detection() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                // This relation references a non-existent relation
                RelationDef::new(
                    "broken".to_string(),
                    Some(RelationExpr::RelationRef { relation: "nonexistent".to_string() }),
                ),
            ],
        )]);

        let analyzer = CoverageAnalyzer::new(&schema);
        let warnings = analyzer.analyze();

        // Should detect that broken has no valid path
        assert!(warnings.iter().any(|w| matches!(
            &w.kind,
            ValidationErrorKind::Coverage(CoverageWarning::UncoveredPermission { .. })
        )));
    }
}
