//! Abstract Syntax Tree for IPL (Infera Policy Language)

use serde::{Deserialize, Serialize};

/// A complete IPL schema
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub types: Vec<TypeDef>,
}

/// A type definition with relations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDef {
    pub name: String,
    pub relations: Vec<RelationDef>,
}

/// A relation definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationDef {
    pub name: String,
    pub expr: Option<RelationExpr>,
}

/// Relation expression
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationExpr {
    /// Direct reference to tuples: `this`
    This,

    /// Reference to another relation: `editor`
    RelationRef {
        relation: String,
    },

    /// Computed userset: `<relation> from <tupleset>`
    ComputedUserset {
        relation: String,
        tupleset: String,
    },

    /// Tuple to userset: `<tupleset>-><computed>`
    TupleToUserset {
        tupleset: String,
        computed: String,
    },

    /// WASM module invocation: `module("name")`
    WasmModule {
        module_name: String,
    },

    /// Union: `expr1 | expr2`
    Union(Vec<RelationExpr>),

    /// Intersection: `expr1 & expr2`
    Intersection(Vec<RelationExpr>),

    /// Exclusion: `expr1 - expr2`
    Exclusion {
        base: Box<RelationExpr>,
        subtract: Box<RelationExpr>,
    },
}

impl Schema {
    pub fn new(types: Vec<TypeDef>) -> Self {
        Self { types }
    }

    /// Find a type by name
    pub fn find_type(&self, name: &str) -> Option<&TypeDef> {
        self.types.iter().find(|t| t.name == name)
    }
}

impl TypeDef {
    pub fn new(name: String, relations: Vec<RelationDef>) -> Self {
        Self { name, relations }
    }

    /// Find a relation by name
    pub fn find_relation(&self, name: &str) -> Option<&RelationDef> {
        self.relations.iter().find(|r| r.name == name)
    }
}

impl RelationDef {
    pub fn new(name: String, expr: Option<RelationExpr>) -> Self {
        Self { name, expr }
    }

    /// Check if this is a direct relation (no expression or `this`)
    pub fn is_direct(&self) -> bool {
        matches!(&self.expr, None | Some(RelationExpr::This))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let schema = Schema::new(vec![
            TypeDef::new(
                "document".to_string(),
                vec![
                    RelationDef::new("viewer".to_string(), Some(RelationExpr::This)),
                ],
            ),
        ]);

        assert_eq!(schema.types.len(), 1);
        assert_eq!(schema.types[0].name, "document");
    }

    #[test]
    fn test_find_type() {
        let schema = Schema::new(vec![
            TypeDef::new("document".to_string(), vec![]),
            TypeDef::new("folder".to_string(), vec![]),
        ]);

        assert!(schema.find_type("document").is_some());
        assert!(schema.find_type("folder").is_some());
        assert!(schema.find_type("nonexistent").is_none());
    }

    #[test]
    fn test_find_relation() {
        let type_def = TypeDef::new(
            "document".to_string(),
            vec![
                RelationDef::new("viewer".to_string(), None),
                RelationDef::new("editor".to_string(), None),
            ],
        );

        assert!(type_def.find_relation("viewer").is_some());
        assert!(type_def.find_relation("editor").is_some());
        assert!(type_def.find_relation("nonexistent").is_none());
    }

    #[test]
    fn test_is_direct() {
        let direct_none = RelationDef::new("viewer".to_string(), None);
        let direct_this = RelationDef::new("viewer".to_string(), Some(RelationExpr::This));
        let computed = RelationDef::new(
            "viewer".to_string(),
            Some(RelationExpr::ComputedUserset {
                relation: "viewer".to_string(),
                tupleset: "parent".to_string(),
            }),
        );

        assert!(direct_none.is_direct());
        assert!(direct_this.is_direct());
        assert!(!computed.is_direct());
    }
}
