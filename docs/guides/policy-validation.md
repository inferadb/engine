# IPL Policy Validation & Static Analysis

InferaDB provides comprehensive static analysis and validation for IPL (Infera Policy Language) schemas. This helps catch errors early, detect potential issues, and improve the quality of your authorization policies.

## Overview

The validation framework consists of three main components:

1. **Type Checker** - Validates that all relation and type references exist
2. **Conflict Detector** - Finds conflicts between permit and forbid rules
3. **Coverage Analyzer** - Identifies unused relations and suggests improvements

## Quick Start

```rust
use infera_core::ipl::{parse_schema, Validator};

let source = r#"
    type document {
        relation owner
        relation viewer: owner
    }
"#;

let schema = parse_schema(source)?;
let validator = Validator::new(&schema);
let results = validator.validate();

if results.has_errors() {
    for error in results.errors() {
        eprintln!("{}", error);
    }
}
```

## Type Checking

The type checker validates that your IPL schema is structurally sound.

### What It Checks

1. **Undefined Relations** - References to relations that don't exist
2. **Undefined Relationships** - Computed usersets referencing non-existent relationships
3. **Circular Dependencies** - Relations that reference each other in a cycle

### Examples

**Error: Undefined Relation**

```ipl
type document {
    relation viewer: editor  // ERROR: 'editor' is not defined
}
```

**Error: Undefined Relationship**

```ipl
type document {
    relation owner
    relation viewer: viewer from parent  // ERROR: 'parent' relationship doesn't exist
}
```

**Error: Circular Dependency**

```ipl
type document {
    relation a: b
    relation b: a  // ERROR: Circular dependency a -> b -> a
}
```

### Usage

```rust
// Run only type checking
let results = validator.type_check();

for error in results.error_messages() {
    eprintln!("Type error: {}", error);
}
```

## Conflict Detection

The conflict detector finds logical issues in your schema that may cause unexpected behavior.

### What It Detects

1. **Permit-Forbid Conflicts** - Same permission has both permit (relation) and forbid rules
2. **Unreachable Relations** - Computed relations that are never referenced
3. **Ambiguous Permissions** - Permissions with multiple contradictory paths

### Examples

**Warning: Permit-Forbid Conflict**

```ipl
type document {
    relation viewer          // Permit rule
    forbid viewer           // Forbid rule with same name
}
```

This creates ambiguity - the permission has both permit and forbid semantics. The forbid will override the permit, but this may be unintentional.

**Warning: Unreachable Relation**

```ipl
type document {
    relation owner
    relation unused: owner   // WARNING: Never referenced by any other relation
}
```

If `unused` is never referenced and has no corresponding forbid, it may be dead code.

### Usage

```rust
// Run only conflict detection
let results = validator.detect_conflicts();

for warning in results.warning_messages() {
    println!("Conflict: {}", warning);
}
```

## Coverage Analysis

The coverage analyzer helps improve your schema by identifying gaps and suggesting tests.

### What It Analyzes

1. **Unused Relations** - Relations defined but never used
2. **Uncovered Permissions** - Permissions with no valid grant path
3. **Missing Test Cases** - Suggestions for test coverage

### Examples

**Info: Unused Relation**

```ipl
type document {
    relation owner
    relation helper: owner   // INFO: May be unused
    relation viewer: owner
}
```

**Info: Test Suggestions**

The analyzer automatically suggests test cases for:

- Direct relations (tuple grants)
- Computed relations (expression evaluation)
- Forbid rules (denial verification)

### Usage

```rust
// Run only coverage analysis
let results = validator.analyze_coverage();

for info in results.info_messages() {
    println!("Coverage: {}", info);
}
```

## Validation Results

The `ValidationResults` object provides detailed information about validation outcomes.

### Methods

```rust
// Check overall validation status
if results.is_valid() {
    println!("Schema is valid!");
}

// Check for specific severities
if results.has_errors() {
    println!("Found {} errors", results.error_messages().len());
}

if results.has_warnings() {
    println!("Found {} warnings", results.warning_messages().len());
}

// Get a summary
println!("{}", results.summary());
```

### Severity Levels

- **Error** - Blocking issues that prevent deployment
- **Warning** - Potential problems that should be reviewed
- **Info** - Suggestions for improvement

## Best Practices

### 1. Validate Before Deployment

Always validate your schemas before deploying to production:

```rust
fn deploy_schema(source: &str) -> Result<()> {
    let schema = parse_schema(source)?;
    let validator = Validator::new(&schema);
    let results = validator.validate();

    if results.has_errors() {
        return Err(anyhow!("Schema validation failed: {}", results.summary()));
    }

    // Proceed with deployment
    Ok(())
}
```

### 2. Address Warnings

While warnings don't block deployment, they often indicate real issues:

```rust
if results.has_warnings() {
    for warning in results.warning_messages() {
        log::warn!("Schema warning: {}", warning);
    }
}
```

### 3. Use Coverage Analysis in CI

Add coverage analysis to your CI pipeline:

```rust
let results = validator.analyze_coverage();

for suggestion in results.info_messages() {
    if suggestion.kind.is_missing_test_case() {
        println!("Missing test: {}", suggestion);
    }
}
```

### 4. Fix Circular Dependencies

Circular dependencies can cause infinite loops or incorrect evaluation:

```ipl
// Bad: Circular dependency
type document {
    relation a: b
    relation b: a
}

// Good: Clear dependency chain
type document {
    relation owner
    relation editor: owner
    relation viewer: editor
}
```

### 5. Avoid Permit-Forbid Conflicts

Be explicit about your intent:

```ipl
// Bad: Ambiguous
type document {
    relation viewer
    forbid viewer
}

// Good: Clear separation
type document {
    relation viewer
    forbid blocked_viewer  // Different name for forbid
}
```

## Integration with Development Workflow

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run validation on all IPL files
find . -name "*.ipl" | while read file; do
    cargo run --bin infera-validate -- "$file"
    if [ $? -ne 0 ]; then
        echo "Schema validation failed for $file"
        exit 1
    fi
done
```

### CI/CD Pipeline

```yaml
# .github/workflows/validate.yml
name: Schema Validation

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
      - name: Validate schemas
        run: cargo test --package infera-core --lib ipl::validation
```

## Error Reference

### Type Check Errors

| Error                   | Description                                      | Fix                                 |
| ----------------------- | ------------------------------------------------ | ----------------------------------- |
| `UndefinedRelation`     | Relation reference doesn't exist                 | Define the relation or fix the typo |
| `UndefinedType`         | Type reference doesn't exist                     | Define the type or fix the typo     |
| `UndefinedRelationship` | Computed userset references missing relationship | Add the relationship to the type    |
| `CircularDependency`    | Relations reference each other in a cycle        | Break the cycle by restructuring    |

### Conflict Warnings

| Warning                | Description                             | Fix                                 |
| ---------------------- | --------------------------------------- | ----------------------------------- |
| `PermitForbidConflict` | Same permission has permit and forbid   | Use different names or review logic |
| `UnreachableRelation`  | Computed relation never referenced      | Remove or add it to a permission    |
| `AmbiguousPermission`  | Multiple contradictory evaluation paths | Simplify the permission logic       |

### Coverage Info

| Info                  | Description              | Action                                  |
| --------------------- | ------------------------ | --------------------------------------- |
| `UnusedRelation`      | Relation may not be used | Add to a permission or remove           |
| `UncoveredPermission` | No valid path to grant   | Add a grant path or mark as unreachable |
| `MissingTestCase`     | Suggested test case      | Add integration test                    |

## Advanced Topics

### Custom Validation Rules

You can implement custom validation logic:

```rust
use infera_core::ipl::validation::{ValidationError, Validator};

fn validate_naming_convention(schema: &Schema) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for type_def in &schema.types {
        if !type_def.name.chars().all(|c| c.is_lowercase() || c == '_') {
            errors.push(ValidationError::new(
                ErrorLocation::type_level(type_def.name.clone()),
                ValidationErrorKind::Custom("Type names should be lowercase".to_string()),
                format!("Type '{}' violates naming convention", type_def.name),
                Some("Use lowercase with underscores (e.g., 'my_type')".to_string()),
            ));
        }
    }

    errors
}
```

### Programmatic Analysis

Build custom tooling on top of the validation framework:

```rust
// Collect all unreachable relations across multiple schemas
let mut unreachable = Vec::new();

for (name, source) in schemas {
    let schema = parse_schema(source)?;
    let validator = Validator::new(&schema);
    let results = validator.detect_conflicts();

    for error in results.warning_messages() {
        if let ValidationErrorKind::Conflict(ConflictError::UnreachableRelation { .. }) = &error.kind {
            unreachable.push((name, error));
        }
    }
}

// Generate report
println!("Found {} unreachable relations across {} schemas",
    unreachable.len(), schemas.len());
```

## Related Documentation

- [IPL Language Reference](../language/ipl.md)
- [Schema Design Patterns](./schema-patterns.md)
- [Testing Policies](./policy-testing.md)
- [Performance Optimization](./performance.md)

## FAQ

**Q: Should I fail deployment on warnings?**

A: It depends on your risk tolerance. Warnings often indicate real issues, but some may be false positives. We recommend logging warnings and reviewing them regularly.

**Q: How do I silence a specific warning?**

A: The validation framework doesn't currently support suppression annotations. If a warning is a false positive, please file an issue.

**Q: Can I validate schemas without Rust code?**

A: Currently, validation requires using the Rust API. A standalone CLI validator is planned for a future release.

**Q: Does validation impact runtime performance?**

A: No. Validation is a static analysis tool that runs during development/deployment, not at runtime.

**Q: What's the difference between unreachable and unused?**

A: "Unreachable" (conflict detector) means a computed relation is never referenced by other relations. "Unused" (coverage analyzer) is similar but provides coverage suggestions. Both help identify dead code.
