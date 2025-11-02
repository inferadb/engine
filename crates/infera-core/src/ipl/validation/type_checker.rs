//! Type checker for IPL schemas
//!
//! Validates that all relation references, type references, and computed usersets
//! reference existing types and relations.

use std::collections::HashSet;

use super::error::{ErrorLocation, TypeCheckError, ValidationError, ValidationErrorKind};
use crate::ipl::ast::{RelationExpr, Schema, TypeDef};

/// Type checker validates references in IPL schemas
pub struct TypeChecker<'a> {
    schema: &'a Schema,
}

impl<'a> TypeChecker<'a> {
    /// Create a new type checker for the given schema
    pub fn new(schema: &'a Schema) -> Self {
        Self { schema }
    }

    /// Run type checking and return all errors found
    pub fn check(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        for type_def in &self.schema.types {
            errors.extend(self.check_type(type_def));
        }

        errors
    }

    /// Check a single type definition
    fn check_type(&self, type_def: &TypeDef) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Check all relations
        for relation in &type_def.relations {
            if let Some(expr) = &relation.expr {
                errors.extend(Self::check_expression(
                    type_def,
                    &relation.name,
                    expr,
                    &mut HashSet::new(),
                ));
            }
        }

        // Check all forbids
        for forbid in &type_def.forbids {
            if let Some(expr) = &forbid.expr {
                errors.extend(Self::check_expression(
                    type_def,
                    &forbid.name,
                    expr,
                    &mut HashSet::new(),
                ));
            }
        }

        // Check for circular dependencies
        for relation in &type_def.relations {
            if let Some(expr) = &relation.expr {
                let mut visited = HashSet::new();
                let mut path = Vec::new();
                if let Some(cycle) = Self::detect_cycle(type_def, expr, &mut visited, &mut path) {
                    errors.push(ValidationError::new(
                        ErrorLocation::relation_level(type_def.name.clone(), relation.name.clone()),
                        ValidationErrorKind::TypeCheck(TypeCheckError::CircularDependency {
                            chain: cycle,
                        }),
                        format!("Circular dependency detected in relation '{}'", relation.name),
                        Some(
                            "Break the circular dependency by restructuring relations".to_string(),
                        ),
                    ));
                }
            }
        }

        errors
    }

    /// Check a relation expression for type correctness
    fn check_expression(
        type_def: &TypeDef,
        relation_name: &str,
        expr: &RelationExpr,
        _visited: &mut HashSet<String>,
    ) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        match expr {
            RelationExpr::This => {
                // Always valid
            },
            RelationExpr::RelationRef { relation } => {
                // Check that the referenced relation exists in this type
                if type_def.find_relation(relation).is_none() {
                    errors.push(ValidationError::new(
                        ErrorLocation::relation_level(
                            type_def.name.clone(),
                            relation_name.to_string(),
                        ),
                        ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelation {
                            referenced: relation.clone(),
                        }),
                        format!(
                            "Relation '{}' references undefined relation '{}'",
                            relation_name, relation
                        ),
                        Some(format!("Define relation '{}' or check for typos", relation)),
                    ));
                }
            },
            RelationExpr::ComputedUserset { relation: _, relationship } => {
                // Check that the relationship exists
                if type_def.find_relation(relationship).is_none() {
                    errors.push(ValidationError::new(
                        ErrorLocation::relation_level(
                            type_def.name.clone(),
                            relation_name.to_string(),
                        ),
                        ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelationship {
                            referenced: relationship.clone(),
                        }),
                        format!(
                            "Computed userset references undefined relationship '{}'",
                            relationship
                        ),
                        Some(format!(
                            "Define relationship '{}' in type '{}'",
                            relationship, type_def.name
                        )),
                    ));
                }

                // The relation will be checked when we evaluate the relationship
                // We can't fully validate it without runtime type information
            },
            RelationExpr::RelatedObjectUserset { relationship, computed: _ } => {
                // Check that the relationship exists in this type
                if type_def.find_relation(relationship).is_none() {
                    errors.push(ValidationError::new(
                        ErrorLocation::relation_level(
                            type_def.name.clone(),
                            relation_name.to_string(),
                        ),
                        ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelationship {
                            referenced: relationship.clone(),
                        }),
                        format!(
                            "Related object userset references undefined relationship '{}'",
                            relationship
                        ),
                        Some(format!(
                            "Define relationship '{}' in type '{}'",
                            relationship, type_def.name
                        )),
                    ));
                }

                // The computed relation will be validated at runtime on the related object
            },
            RelationExpr::WasmModule { module_name: _ } => {
                // WASM modules are validated at runtime, not during static analysis
            },
            RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => {
                for sub_expr in exprs {
                    errors.extend(Self::check_expression(
                        type_def,
                        relation_name,
                        sub_expr,
                        _visited,
                    ));
                }
            },
            RelationExpr::Exclusion { base, subtract } => {
                errors.extend(Self::check_expression(type_def, relation_name, base, _visited));
                errors.extend(Self::check_expression(type_def, relation_name, subtract, _visited));
            },
        }

        errors
    }

    /// Detect circular dependencies in relation expressions
    fn detect_cycle(
        type_def: &TypeDef,
        expr: &RelationExpr,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        match expr {
            RelationExpr::RelationRef { relation } => {
                if path.contains(relation) {
                    // Found a cycle
                    let cycle_start = path.iter().position(|r| r == relation).unwrap();
                    return Some(path[cycle_start..].to_vec());
                }

                if visited.contains(relation) {
                    // Already checked this branch
                    return None;
                }

                path.push(relation.clone());
                visited.insert(relation.clone());

                if let Some(rel_def) = type_def.find_relation(relation) {
                    if let Some(rel_expr) = &rel_def.expr {
                        let cycle = Self::detect_cycle(type_def, rel_expr, visited, path);
                        if cycle.is_some() {
                            return cycle;
                        }
                    }
                }

                path.pop();
                None
            },
            RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => {
                for sub_expr in exprs {
                    let cycle = Self::detect_cycle(type_def, sub_expr, visited, path);
                    if cycle.is_some() {
                        return cycle;
                    }
                }
                None
            },
            RelationExpr::Exclusion { base, subtract } => {
                let cycle = Self::detect_cycle(type_def, base, visited, path);
                if cycle.is_some() {
                    return cycle;
                }
                let cycle = Self::detect_cycle(type_def, subtract, visited, path);
                if cycle.is_some() {
                    return cycle;
                }
                None
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipl::ast::{RelationDef, RelationExpr, Schema, TypeDef};

    #[test]
    fn test_valid_schema() {
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

        let checker = TypeChecker::new(&schema);
        let errors = checker.check();

        assert_eq!(errors.len(), 0);
    }

    #[test]
    fn test_undefined_relation() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::RelationRef { relation: "nonexistent".to_string() }),
            )],
        )]);

        let checker = TypeChecker::new(&schema);
        let errors = checker.check();

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelation { .. })
        ));
    }

    #[test]
    fn test_undefined_relationship_computed_userset() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::ComputedUserset {
                    relation: "viewer".to_string(),
                    relationship: "nonexistent".to_string(),
                }),
            )],
        )]);

        let checker = TypeChecker::new(&schema);
        let errors = checker.check();

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelationship { .. })
        ));
    }

    #[test]
    fn test_circular_dependency() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new(
                    "a".to_string(),
                    Some(RelationExpr::RelationRef { relation: "b".to_string() }),
                ),
                RelationDef::new(
                    "b".to_string(),
                    Some(RelationExpr::RelationRef { relation: "a".to_string() }),
                ),
            ],
        )]);

        let checker = TypeChecker::new(&schema);
        let errors = checker.check();

        // Should detect circular dependency
        assert!(errors.iter().any(|e| matches!(
            &e.kind,
            ValidationErrorKind::TypeCheck(TypeCheckError::CircularDependency { .. })
        )));
    }

    #[test]
    fn test_union_with_undefined_relation() {
        let schema = Schema::new(vec![TypeDef::new(
            "document".to_string(),
            vec![RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Union(vec![
                    RelationExpr::This,
                    RelationExpr::RelationRef { relation: "nonexistent".to_string() },
                ])),
            )],
        )]);

        let checker = TypeChecker::new(&schema);
        let errors = checker.check();

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::TypeCheck(TypeCheckError::UndefinedRelation { .. })
        ));
    }
}
