//! IPL (Infera Policy Language) parser and interpreter

pub mod ast;
pub mod parser;
pub mod validation;

// Re-export main types
pub use ast::{ForbidDef, RelationDef, RelationExpr, Schema, TypeDef};
pub use parser::parse_schema;
pub use validation::{ValidationError, ValidationResults, Validator};
