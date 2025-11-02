//! Conflict detector for IPL schemas
//!
//! Detects conflicts between permit and forbid rules, unreachable relations,
//! and ambiguous permission paths.

use std::collections::HashSet;

use super::error::{ConflictError, ErrorLocation, ValidationError, ValidationErrorKind};
use crate::ipl::ast::{RelationExpr, Schema, TypeDef};

/// Conflict detector finds issues in IPL schemas
pub struct ConflictDetector<'a> {
    schema: &'a Schema,
}

impl<'a> ConflictDetector<'a> {
    /// Create a new conflict detector for the given schema
    pub fn new(schema: &'a Schema) -> Self {
        Self { schema }
    }

    /// Run conflict detection and return all conflicts found
    pub fn detect(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        for type_def in &self.schema.types {
            errors.extend(self.detect_type_conflicts(type_def));
        }

        errors
    }

    /// Detect conflicts in a single type definition
    fn detect_type_conflicts(&self, type_def: &TypeDef) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Check for permit-forbid conflicts
        errors.extend(self.detect_permit_forbid_conflicts(type_def));

        // Check for unreachable relations
        errors.extend(self.detect_unreachable_relations(type_def));

        errors
    }

    /// Detect conflicts between permit (relations) and forbid rules
    fn detect_permit_forbid_conflicts(&self, type_def: &TypeDef) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // For each forbid, check if it conflicts with any relation of the same name
        for forbid in &type_def.forbids {
            if let Some(relation) = type_def.find_relation(&forbid.name) {
                // Check if they might overlap
                if self.expressions_may_overlap(relation.expr.as_ref(), forbid.expr.as_ref()) {
                    errors.push(ValidationError::new(
                        ErrorLocation::type_level(type_def.name.clone()),
                        ValidationErrorKind::Conflict(ConflictError::PermitForbidConflict {
                            permission: forbid.name.clone(),
                            forbid_name: forbid.name.clone(),
                        }),
                        format!(
                            "Permission '{}' has both permit (relation) and forbid rules that may conflict",
                            forbid.name
                        ),
                        Some(
                            "Review the logic to ensure forbid rules properly override permits".to_string()
                        ),
                    ));
                }
            }
        }

        errors
    }

    /// Check if two expressions may overlap in their evaluation
    fn expressions_may_overlap(
        &self,
        expr1: Option<&RelationExpr>,
        expr2: Option<&RelationExpr>,
    ) -> bool {
        // Conservative check: if either is None (direct reference) or This, they overlap
        match (expr1, expr2) {
            (None, _) | (_, None) => true,
            (Some(RelationExpr::This), _) | (_, Some(RelationExpr::This)) => true,
            // For complex expressions, we conservatively assume they may overlap
            // A more sophisticated analysis would track the actual usersets
            _ => true,
        }
    }

    /// Detect relations that are defined but never used
    fn detect_unreachable_relations(&self, type_def: &TypeDef) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Build a graph of which relations reference which
        let mut referenced = HashSet::new();

        for relation in &type_def.relations {
            if let Some(expr) = &relation.expr {
                Self::collect_references(expr, &mut referenced);
            }
        }

        for forbid in &type_def.forbids {
            if let Some(expr) = &forbid.expr {
                Self::collect_references(expr, &mut referenced);
            }
        }

        // Find relations that are never referenced
        for relation in &type_def.relations {
            // Skip direct relations (they're always reachable via tuples)
            if relation.is_direct() {
                continue;
            }

            // Check if this relation is referenced by any other relation or forbid
            let is_referenced = referenced.contains(&relation.name);

            // Check if this relation has the same name as any forbid (it's used for permission
            // checks)
            let has_forbid = type_def.find_forbid(&relation.name).is_some();

            if !is_referenced && !has_forbid {
                errors.push(ValidationError::new(
                    ErrorLocation::relation_level(type_def.name.clone(), relation.name.clone()),
                    ValidationErrorKind::Conflict(ConflictError::UnreachableRelation {
                        relation: relation.name.clone(),
                        reason: "Relation is computed but never referenced".to_string(),
                    }),
                    format!(
                        "Relation '{}' is defined but never used in any permission check",
                        relation.name
                    ),
                    Some("Remove the unused relation or add it to a permission check".to_string()),
                ));
            }
        }

        errors
    }

    /// Collect all relation references from an expression
    fn collect_references(expr: &RelationExpr, refs: &mut HashSet<String>) {
        match expr {
            RelationExpr::RelationRef { relation } => {
                refs.insert(relation.clone());
            },
            RelationExpr::ComputedUserset { relation: _, relationship } => {
                refs.insert(relationship.clone());
                // Note: `relation` is on the related object, not directly referenced here
            },
            RelationExpr::RelatedObjectUserset { relationship, computed: _ } => {
                refs.insert(relationship.clone());
            },
            RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => {
                for sub_expr in exprs {
                    Self::collect_references(sub_expr, refs);
                }
            },
            RelationExpr::Exclusion { base, subtract } => {
                Self::collect_references(base, refs);
                Self::collect_references(subtract, refs);
            },
            RelationExpr::This | RelationExpr::WasmModule { .. } => {
                // No references
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipl::ast::{ForbidDef, RelationDef, RelationExpr, Schema, TypeDef};

    #[test]
    fn test_no_conflicts() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new("viewer".to_string(), None),
            ],
        )]);

        let detector = ConflictDetector::new(&schema);
        let errors = detector.detect();

        // Both owner and viewer are direct relations, so no conflicts
        assert_eq!(errors.len(), 0);
    }

    #[test]
    fn test_permit_forbid_conflict() {
        let schema = Schema::new(vec![TypeDef::new_with_forbids(
            "document".to_string(),
            vec![RelationDef::new("viewer".to_string(), None)],
            vec![ForbidDef::new("viewer".to_string(), None)],
        )]);

        let detector = ConflictDetector::new(&schema);
        let errors = detector.detect();

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::Conflict(ConflictError::PermitForbidConflict { .. })
        ));
    }

    #[test]
    fn test_unreachable_relation() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::This)),
                // unused_relation is computed but never referenced
                RelationDef::new(
                    "unused_relation".to_string(),
                    Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
                ),
            ],
        )]);

        let detector = ConflictDetector::new(&schema);
        let errors = detector.detect();

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::Conflict(ConflictError::UnreachableRelation { .. })
        ));
    }

    #[test]
    fn test_reachable_through_union() {
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
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                    ])),
                ),
            ],
        )]);

        let detector = ConflictDetector::new(&schema);
        let errors = detector.detect();

        // editor is referenced by viewer, so it's not unreachable
        // However, viewer itself is unreachable (not referenced by anything)
        // This is actually correct - computed permissions that aren't referenced
        // anywhere may be dead code (unless used as a top-level permission in checks)
        let unreachable_errors: Vec<_> = errors
            .iter()
            .filter(|e| {
                matches!(
                    &e.kind,
                    ValidationErrorKind::Conflict(ConflictError::UnreachableRelation {
                        relation,
                        ..
                    }) if relation == "viewer"
                )
            })
            .collect();

        // viewer is flagged as unreachable (correct behavior - it's not referenced)
        assert_eq!(unreachable_errors.len(), 1);
    }

    #[test]
    fn test_relation_used_by_forbid_not_unreachable() {
        let schema = Schema::new(vec![TypeDef::new_with_forbids(
            "document".to_string(),
            vec![RelationDef::new("blocked".to_string(), Some(RelationExpr::This))],
            vec![ForbidDef::new("blocked".to_string(), None)],
        )]);

        let detector = ConflictDetector::new(&schema);
        let errors = detector.detect();

        // blocked relation is used by forbid with same name, so not unreachable
        let unreachable_errors: Vec<_> = errors
            .iter()
            .filter(|e| {
                matches!(
                    &e.kind,
                    ValidationErrorKind::Conflict(ConflictError::UnreachableRelation { .. })
                )
            })
            .collect();

        assert_eq!(unreachable_errors.len(), 0);
    }
}
