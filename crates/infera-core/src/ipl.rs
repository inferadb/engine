//! IPL (Infera Policy Language) parser and interpreter

pub mod ast;
pub mod parser;

// Re-export main types
pub use ast::{RelationDef, RelationExpr, Schema, TypeDef};
pub use parser::parse_schema;

use crate::Result;
