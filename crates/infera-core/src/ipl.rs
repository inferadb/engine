//! IPL (Infera Policy Language) parser and interpreter

pub mod ast;
pub mod parser;

// Re-export main types
pub use ast::{RelationDef, RelationExpr, Schema, TypeDef};
pub use parser::parse_schema;

use crate::Result;

/// Parse IPL policy definition (alias for parse_schema)
#[deprecated(note = "Use parse_schema instead")]
pub fn parse_policy(source: &str) -> Result<Schema> {
    parse_schema(source)
}
