//! IPL Parser implementation using pest

use pest::Parser;
use pest_derive::Parser;

use super::ast::*;
use crate::{EvalError, Result};

#[derive(Parser)]
#[grammar = "ipl.pest"]
pub struct IPLParser;

/// Parse an IPL schema from source text
pub fn parse_schema(source: &str) -> Result<Schema> {
    let pairs = IPLParser::parse(Rule::schema, source)
        .map_err(|e| EvalError::Parse(format!("Parse error: {}", e)))?;

    let mut types = Vec::new();

    for pair in pairs {
        match pair.as_rule() {
            Rule::schema => {
                for inner in pair.into_inner() {
                    match inner.as_rule() {
                        Rule::type_def => {
                            types.push(parse_type_def(inner)?);
                        }
                        Rule::EOI => {}
                        _ => unreachable!("Unexpected rule: {:?}", inner.as_rule()),
                    }
                }
            }
            _ => unreachable!("Unexpected rule: {:?}", pair.as_rule()),
        }
    }

    Ok(Schema::new(types))
}

fn parse_type_def(pair: pest::iterators::Pair<Rule>) -> Result<TypeDef> {
    let mut inner = pair.into_inner();

    let name = inner
        .next()
        .ok_or_else(|| EvalError::Parse("Expected type name".to_string()))?
        .as_str()
        .to_string();

    let mut relations = Vec::new();
    let mut forbids = Vec::new();

    for def_pair in inner {
        match def_pair.as_rule() {
            Rule::relation_def => {
                relations.push(parse_relation_def(def_pair)?);
            }
            Rule::forbid_def => {
                forbids.push(parse_forbid_def(def_pair)?);
            }
            _ => {}
        }
    }

    Ok(TypeDef::new_with_forbids(name, relations, forbids))
}

fn parse_relation_def(pair: pest::iterators::Pair<Rule>) -> Result<RelationDef> {
    let mut inner = pair.into_inner();

    let name = inner
        .next()
        .ok_or_else(|| EvalError::Parse("Expected relation name".to_string()))?
        .as_str()
        .to_string();

    let expr = if let Some(expr_pair) = inner.next() {
        Some(parse_relation_expr(expr_pair)?)
    } else {
        None
    };

    Ok(RelationDef::new(name, expr))
}

fn parse_forbid_def(pair: pest::iterators::Pair<Rule>) -> Result<ForbidDef> {
    let mut inner = pair.into_inner();

    let name = inner
        .next()
        .ok_or_else(|| EvalError::Parse("Expected forbid name".to_string()))?
        .as_str()
        .to_string();

    let expr = if let Some(expr_pair) = inner.next() {
        Some(parse_relation_expr(expr_pair)?)
    } else {
        None
    };

    Ok(ForbidDef::new(name, expr))
}

fn parse_relation_expr(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    match pair.as_rule() {
        Rule::relation_expr => {
            let inner = pair
                .into_inner()
                .next()
                .ok_or_else(|| EvalError::Parse("Expected expression".to_string()))?;
            parse_relation_expr(inner)
        }
        Rule::union_expr => parse_union_expr(pair),
        Rule::intersection_expr => parse_intersection_expr(pair),
        Rule::exclusion_expr => parse_exclusion_expr(pair),
        Rule::primary_expr => parse_primary_expr(pair),
        _ => Err(EvalError::Parse(format!(
            "Unexpected rule: {:?}",
            pair.as_rule()
        ))),
    }
}

fn parse_union_expr(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    let mut exprs = Vec::new();

    for inner in pair.into_inner() {
        exprs.push(parse_intersection_expr(inner)?);
    }

    if exprs.len() == 1 {
        Ok(exprs.into_iter().next().unwrap())
    } else {
        Ok(RelationExpr::Union(exprs))
    }
}

fn parse_intersection_expr(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    let mut exprs = Vec::new();

    for inner in pair.into_inner() {
        exprs.push(parse_exclusion_expr(inner)?);
    }

    if exprs.len() == 1 {
        Ok(exprs.into_iter().next().unwrap())
    } else {
        Ok(RelationExpr::Intersection(exprs))
    }
}

fn parse_exclusion_expr(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    let mut inner = pair.into_inner();
    let base = parse_primary_expr(
        inner
            .next()
            .ok_or_else(|| EvalError::Parse("Expected base expression".to_string()))?,
    )?;

    if let Some(subtract_pair) = inner.next() {
        let subtract = parse_primary_expr(subtract_pair)?;
        Ok(RelationExpr::Exclusion {
            base: Box::new(base),
            subtract: Box::new(subtract),
        })
    } else {
        Ok(base)
    }
}

fn parse_primary_expr(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| EvalError::Parse("Expected primary expression".to_string()))?;

    match inner.as_rule() {
        Rule::this_ref => Ok(RelationExpr::This),
        Rule::relation_ref => Ok(RelationExpr::RelationRef {
            relation: inner.as_str().to_string(),
        }),
        Rule::computed_userset => parse_computed_userset(inner),
        Rule::tuple_to_userset => parse_related_object_userset(inner),
        Rule::wasm_module => parse_wasm_module(inner),
        Rule::relation_expr => parse_relation_expr(inner),
        _ => Err(EvalError::Parse(format!(
            "Unexpected primary expression: {:?}",
            inner.as_rule()
        ))),
    }
}

fn parse_computed_userset(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    let mut inner = pair.into_inner();

    let relation = inner
        .next()
        .ok_or_else(|| EvalError::Parse("Expected relation name".to_string()))?
        .as_str()
        .to_string();

    let relationship = inner
        .next()
        .ok_or_else(|| EvalError::Parse("Expected relationship name".to_string()))?
        .as_str()
        .to_string();

    Ok(RelationExpr::ComputedUserset {
        relation,
        relationship,
    })
}

fn parse_related_object_userset(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    let mut inner = pair.into_inner();

    let relationship = inner
        .next()
        .ok_or_else(|| EvalError::Parse("Expected relationship name".to_string()))?
        .as_str()
        .to_string();

    let computed = inner
        .next()
        .ok_or_else(|| EvalError::Parse("Expected computed relation name".to_string()))?
        .as_str()
        .to_string();

    Ok(RelationExpr::RelatedObjectUserset {
        relationship,
        computed,
    })
}

fn parse_wasm_module(pair: pest::iterators::Pair<Rule>) -> Result<RelationExpr> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| EvalError::Parse("Expected module name string".to_string()))?;

    // The string rule is atomic (@), so we need to strip the quotes manually
    let raw_string = inner.as_str();
    let module_name = raw_string.trim_matches('"').to_string();

    Ok(RelationExpr::WasmModule { module_name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_schema() {
        let result = parse_schema("");
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types.len(), 0);
    }

    #[test]
    fn test_parse_simple_type() {
        let source = r#"
            type document {
                relation viewer
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types.len(), 1);
        assert_eq!(schema.types[0].name, "document");
        assert_eq!(schema.types[0].relations.len(), 1);
        assert_eq!(schema.types[0].relations[0].name, "viewer");
    }

    #[test]
    fn test_parse_type_with_this() {
        let source = r#"
            type document {
                relation viewer: this
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types[0].relations[0].expr, Some(RelationExpr::This));
    }

    #[test]
    fn test_parse_computed_userset() {
        let source = r#"
            type document {
                relation viewer: viewer from parent
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();

        match &schema.types[0].relations[0].expr {
            Some(RelationExpr::ComputedUserset {
                relation,
                relationship,
            }) => {
                assert_eq!(relation, "viewer");
                assert_eq!(relationship, "parent");
            }
            _ => panic!("Expected ComputedUserset"),
        }
    }

    #[test]
    fn test_parse_related_object_userset() {
        let source = r#"
            type document {
                relation viewer: parent->viewer
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();

        match &schema.types[0].relations[0].expr {
            Some(RelationExpr::RelatedObjectUserset {
                relationship,
                computed,
            }) => {
                assert_eq!(relationship, "parent");
                assert_eq!(computed, "viewer");
            }
            _ => panic!("Expected RelatedObjectUserset"),
        }
    }

    #[test]
    fn test_parse_union() {
        let source = r#"
            type document {
                relation viewer: this | editor
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();

        match &schema.types[0].relations[0].expr {
            Some(RelationExpr::Union(exprs)) => {
                assert_eq!(exprs.len(), 2);
            }
            _ => panic!("Expected Union"),
        }
    }

    #[test]
    fn test_parse_intersection() {
        let source = r#"
            type document {
                relation viewer: this & editor
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();

        match &schema.types[0].relations[0].expr {
            Some(RelationExpr::Intersection(exprs)) => {
                assert_eq!(exprs.len(), 2);
            }
            _ => panic!("Expected Intersection"),
        }
    }

    #[test]
    fn test_parse_exclusion() {
        let source = r#"
            type document {
                relation viewer: editor - blocked
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();

        match &schema.types[0].relations[0].expr {
            Some(RelationExpr::Exclusion {
                base: _,
                subtract: _,
            }) => {
                // Success
            }
            _ => panic!("Expected Exclusion"),
        }
    }

    #[test]
    fn test_parse_wasm_module() {
        let source = r#"
            type document {
                relation viewer: module("business_hours")
            }
        "#;

        let result = parse_schema(source);
        if result.is_err() {
            eprintln!("Parse error: {:?}", result.as_ref().unwrap_err());
        }
        assert!(result.is_ok());
        let schema = result.unwrap();

        match &schema.types[0].relations[0].expr {
            Some(RelationExpr::WasmModule { module_name }) => {
                assert_eq!(module_name, "business_hours");
            }
            _ => panic!("Expected WasmModule"),
        }
    }

    #[test]
    fn test_parse_complex_schema() {
        let source = r#"
            type folder {
                relation owner
                relation viewer: this | owner
            }

            type document {
                relation parent
                relation owner
                relation editor: this | owner
                relation viewer: this | editor | viewer from parent
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types.len(), 2);

        let folder = &schema.types[0];
        assert_eq!(folder.name, "folder");
        assert_eq!(folder.relations.len(), 2);

        let document = &schema.types[1];
        assert_eq!(document.name, "document");
        assert_eq!(document.relations.len(), 4);
    }

    #[test]
    fn test_parse_with_comments() {
        let source = r#"
            // This is a document type
            type document {
                // Owner relation
                relation owner
                // Viewers can be editors or owners
                relation viewer: this | owner
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_syntax() {
        let source = "type document { relation }";
        let result = parse_schema(source);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_simple_forbid() {
        let source = r#"
            type document {
                relation viewer
                forbid blocked
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types.len(), 1);
        assert_eq!(schema.types[0].name, "document");
        assert_eq!(schema.types[0].relations.len(), 1);
        assert_eq!(schema.types[0].forbids.len(), 1);
        assert_eq!(schema.types[0].forbids[0].name, "blocked");
    }

    #[test]
    fn test_parse_forbid_with_expression() {
        let source = r#"
            type document {
                relation viewer
                relation editor
                relation blocked_user
                forbid denied: blocked_user | editor
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types[0].forbids.len(), 1);
        assert_eq!(schema.types[0].forbids[0].name, "denied");

        // Check that the expression is a union
        match &schema.types[0].forbids[0].expr {
            Some(RelationExpr::Union(_)) => {
                // Success
            }
            _ => panic!("Expected Union expression in forbid"),
        }
    }

    #[test]
    fn test_parse_multiple_forbids() {
        let source = r#"
            type document {
                relation viewer
                forbid blocked
                forbid suspended
                forbid banned: this | viewer
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types[0].forbids.len(), 3);
        assert_eq!(schema.types[0].forbids[0].name, "blocked");
        assert_eq!(schema.types[0].forbids[1].name, "suspended");
        assert_eq!(schema.types[0].forbids[2].name, "banned");
    }

    #[test]
    fn test_parse_forbid_with_wasm() {
        let source = r#"
            type document {
                relation viewer
                forbid time_restricted: module("business_hours")
            }
        "#;

        let result = parse_schema(source);
        assert!(result.is_ok());
        let schema = result.unwrap();
        assert_eq!(schema.types[0].forbids.len(), 1);

        match &schema.types[0].forbids[0].expr {
            Some(RelationExpr::WasmModule { module_name }) => {
                assert_eq!(module_name, "business_hours");
            }
            _ => panic!("Expected WasmModule in forbid"),
        }
    }
}
