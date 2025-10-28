//! IPL (Infera Policy Language) parser and interpreter

use crate::{EvalError, Result};

/// Parse IPL policy definition
pub fn parse_policy(source: &str) -> Result<Policy> {
    // TODO: Implement pest-based parser
    // For now, return a placeholder
    Err(EvalError::Parse("Not yet implemented".to_string()))
}

/// A parsed policy definition
#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub name: String,
    pub definition: RelationDefinition,
}

#[derive(Debug, Clone)]
pub enum RelationDefinition {
    This,
    ComputedUserset { relation: String },
    TupleToUserset { tupleset: String, computed: String },
    Union(Vec<RelationDefinition>),
    Intersection(Vec<RelationDefinition>),
    Exclusion { base: Box<RelationDefinition>, subtract: Box<RelationDefinition> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_placeholder() {
        let result = parse_policy("type document");
        assert!(result.is_err());
    }
}
