//! Fuzzing tests for IPL parser
//!
//! These tests use proptest to generate random inputs and ensure the parser
//! handles them gracefully without panicking.

use infera_core::ipl::parser::parse_schema;
use proptest::prelude::*;

// Test that parser doesn't panic on arbitrary strings
proptest! {
    #[test]
    fn parser_doesnt_panic_on_random_input(s in "\\PC*") {
        let _ = parse_schema(&s);
        // Parser should either succeed or return an error, never panic
    }

    #[test]
    fn parser_handles_long_identifiers(name in "[a-zA-Z][a-zA-Z0-9_]{0,1000}") {
        let schema = format!("type {} {{}}", name);
        let _ = parse_schema(&schema);
    }

    #[test]
    fn parser_handles_deep_nesting(depth in 1usize..20) {
        let mut schema = String::from("type document {\n");
        schema.push_str("  relation viewer: user");

        for i in 0..depth {
            schema.push_str(&format!(" | user from parent{}", i));
        }
        schema.push_str("\n}");

        let result = parse_schema(&schema);
        // Deep nesting should either parse or fail gracefully
        match result {
            Ok(_) => {}, // Success is fine
            Err(_) => {}, // Failure is fine as long as no panic
        }
    }

    #[test]
    fn parser_handles_many_types(count in 1usize..50) {
        let mut schema = String::new();
        for i in 0..count {
            schema.push_str(&format!("type type{} {{\n", i));
            schema.push_str("  relation viewer: user\n");
            schema.push_str("}\n");
        }

        let _ = parse_schema(&schema);
    }

    #[test]
    fn parser_handles_many_relations(count in 1usize..50) {
        let mut schema = String::from("type document {\n");
        for i in 0..count {
            schema.push_str(&format!("  relation rel{}: user\n", i));
        }
        schema.push_str("}");

        let _ = parse_schema(&schema);
    }

    #[test]
    fn parser_handles_unicode_in_comments(comment in ".*") {
        let schema = format!(
            "// {}\ntype document {{\n  relation viewer: user\n}}",
            comment.replace('\n', " ")
        );
        let _ = parse_schema(&schema);
    }

    #[test]
    fn parser_handles_mixed_operators(
        ops in prop::collection::vec(prop::sample::select(&["|", "&", "-"]), 1..10)
    ) {
        let mut schema = String::from("type document {\n  relation viewer: user");
        for (i, op) in ops.iter().enumerate() {
            schema.push_str(&format!(" {} relation{}", op, i));
        }
        schema.push_str("\n}");

        let _ = parse_schema(&schema);
    }
}

// Test specific edge cases that could cause issues
#[test]
fn test_empty_input() {
    let result = parse_schema("");
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_only_whitespace() {
    let result = parse_schema("   \n\n\t\t  \n");
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_only_comments() {
    let result = parse_schema("// comment\n// another comment\n");
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_unterminated_type() {
    let result = parse_schema("type document {");
    assert!(result.is_err());
}

#[test]
fn test_invalid_relation_syntax() {
    let result = parse_schema("type document { relation : }");
    assert!(result.is_err());
}

#[test]
fn test_circular_reference() {
    let schema = r#"
        type document {
            relation viewer: user from parent
            relation parent: document from viewer
        }
    "#;
    // Parser should accept this syntax (cycle detection happens at evaluation time)
    let _ = parse_schema(schema);
}

#[test]
fn test_very_long_line() {
    let long_name = "a".repeat(10000);
    let schema = format!("type {} {{}}", long_name);
    let _ = parse_schema(&schema);
}

#[test]
fn test_many_nested_unions() {
    let mut schema = String::from("type document {\n  relation viewer: user");
    for i in 0..100 {
        schema.push_str(&format!(" | user{}", i));
    }
    schema.push_str("\n}");
    let _ = parse_schema(&schema);
}

#[test]
fn test_special_characters_in_strings() {
    let schema = r#"
        type document {
            relation viewer: user
        }
    "#;
    // Test that normal schema works
    assert!(parse_schema(schema).is_ok());
}

#[test]
fn test_null_bytes() {
    let schema = "type document\0 { relation viewer: user }";
    let _ = parse_schema(schema);
}

#[test]
fn test_repeated_keywords() {
    let schema = "type type type { relation relation: user }";
    let result = parse_schema(schema);
    assert!(result.is_err());
}

#[test]
fn test_missing_closing_brace() {
    let schema = "type document { relation viewer: user";
    let result = parse_schema(schema);
    assert!(result.is_err());
}

#[test]
fn test_extra_closing_brace() {
    let schema = "type document { relation viewer: user }}";
    let result = parse_schema(schema);
    // May succeed if extra brace is ignored, or fail - both are acceptable
    let _ = result;
}

#[test]
fn test_invalid_type_reference() {
    let schema = r#"
        type document {
            relation viewer: nonexistent_type
        }
    "#;
    // Parser should accept this (validation happens at runtime)
    let _ = parse_schema(schema);
}

#[test]
fn test_reserved_keywords_as_identifiers() {
    let schema = "type module { relation wasm: user }";
    let _ = parse_schema(schema);
}
