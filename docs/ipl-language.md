# IPL (Infera Policy Language)

IPL is InferaDB's domain-specific language for defining authorization policies. It provides a concise, declarative syntax for expressing complex relationship-based access control rules.

## Overview

IPL schemas define **types** and their **relations**. Relations can be:
- Direct (stored as tuples)
- Computed (derived from other relations)
- Combined using set operations (union, intersection, exclusion)

## Basic Syntax

### Type Definitions

```ipl
type document {
    relation viewer
    relation editor
    relation owner
}
```

A type represents a resource class (e.g., documents, folders, organizations). Each type has a set of relations that define how users relate to resources of that type.

### Direct Relations

The simplest relation is a direct relation, which corresponds to stored tuples:

```ipl
type document {
    relation viewer   // Equivalent to: relation viewer = this
}
```

When a tuple `document:readme#viewer@user:alice` exists in the store, user Alice is directly a viewer of the readme document.

### Explicit `this` Keyword

```ipl
type document {
    relation viewer = this
}
```

The `this` keyword explicitly indicates a direct relation backed by stored tuples.

## Computed Relations

### Union (OR) - `|`

Union combines multiple relations. A user has the relation if they have ANY of the component relations:

```ipl
type document {
    relation viewer
    relation editor
    relation owner

    relation can_view = viewer | editor | owner
}
```

**Semantics**: User has `can_view` if they are a `viewer` OR `editor` OR `owner`.

**Example tuples**:
```
document:readme#editor@user:alice
```
Query: `Check(user:alice, document:readme, can_view)` → **Allow**

### Intersection (AND) - `&`

Intersection requires all component relations. A user has the relation only if they have ALL of the component relations:

```ipl
type document {
    relation viewer
    relation sensitive_clearance

    relation can_view_sensitive = viewer & sensitive_clearance
}
```

**Semantics**: User has `can_view_sensitive` only if they are BOTH a `viewer` AND have `sensitive_clearance`.

**Example tuples**:
```
document:secret#viewer@user:alice
document:secret#sensitive_clearance@user:alice
```
Query: `Check(user:alice, document:secret, can_view_sensitive)` → **Allow**

### Exclusion (EXCEPT) - `-`

Exclusion removes users from a relation. A user has the relation if they have the base relation but NOT the subtract relation:

```ipl
type document {
    relation viewer
    relation blocked

    relation can_view = viewer - blocked
}
```

**Semantics**: User has `can_view` if they are a `viewer` AND NOT `blocked`.

**Example tuples**:
```
document:readme#viewer@user:alice
document:readme#viewer@user:bob
document:readme#blocked@user:bob
```
Queries:
- `Check(user:alice, document:readme, can_view)` → **Allow**
- `Check(user:bob, document:readme, can_view)` → **Deny** (blocked)

## Relation References

### Computed Userset

Reference another relation on the same resource:

```ipl
type document {
    relation editor
    relation viewer = editor  // Editors are also viewers
}
```

**Semantics**: Anyone with the `editor` relation automatically has the `viewer` relation.

### Tuple-to-Userset (Indirect Relations)

Follow a relation to another resource, then check a relation on that resource:

```ipl
type folder {
    relation viewer
    relation parent: folder  // Parent is a folder

    relation can_view = viewer | viewer from parent
}
```

**Semantics**:
1. User is directly a `viewer` of the folder, OR
2. User is a `viewer` of the parent folder (inherited access)

**Example tuples**:
```
folder:root#viewer@user:alice
folder:sub#parent@folder:root
```
Query: `Check(user:alice, folder:sub, can_view)` → **Allow** (inherited from root)

**Syntax**: `<relation> from <tupleset_relation>`

## Complex Examples

### Document Hierarchy with Organizations

```ipl
type user {
    relation member_of: organization
}

type organization {
    relation member
}

type folder {
    relation owner
    relation viewer
    relation parent: folder
    relation org: organization

    relation can_view = viewer | owner | viewer from parent | member from org
}

type document {
    relation owner
    relation viewer
    relation parent: folder

    relation can_view = viewer | owner | can_view from parent
    relation can_edit = owner
    relation can_delete = owner
}
```

**Access Patterns**:
1. Direct viewer/owner
2. Inherited from parent folder
3. Organization membership grants access
4. Transitive through folder hierarchy

### Multi-Level Approval

```ipl
type approval_request {
    relation requester
    relation approver
    relation admin

    relation pending = requester - approver
    relation approved = requester & approver
    relation can_approve = approver | admin
}
```

**Semantics**:
- `pending`: Has requested but not yet approved
- `approved`: Both requested and approved
- `can_approve`: Can approve requests (approvers or admins)

## WASM Module Invocations

IPL supports custom logic via WebAssembly modules:

```ipl
type document {
    relation viewer

    relation can_view_during_hours = viewer & module("business_hours")
}
```

The WASM module receives execution context and returns 0 (deny) or non-zero (allow).

**WASM Module Interface**:
```rust
struct ExecutionContext {
    subject: String,
    resource: String,
    permission: String,
    context: Option<serde_json::Value>,
}

// WASM function signature:
fn check() -> i32 {
    // Return 0 for deny, 1 for allow
}
```

## Grammar Reference

### Types

```ebnf
schema       = type_def+
type_def     = "type" IDENT "{" relation_def+ "}"
```

### Relations

```ebnf
relation_def = "relation" IDENT (":" type_ref)? ("=" expr)?
type_ref     = IDENT
```

### Expressions

```ebnf
expr         = union_expr
union_expr   = intersect_expr ("|" intersect_expr)*
intersect_expr = exclusion_expr ("&" exclusion_expr)*
exclusion_expr = primary_expr ("-" primary_expr)?

primary_expr = "this"
             | IDENT                          // relation reference
             | IDENT "from" IDENT            // tuple-to-userset
             | "module" "(" STRING ")"       // WASM module
             | "(" expr ")"                   // grouping
```

## Evaluation Semantics

### Direct Tuple Lookup

When evaluating `relation viewer = this`:
1. Query store for tuples: `<resource>#viewer@*`
2. Check if user is in result set

### Computed Relation Evaluation

When evaluating `relation can_view = viewer | editor`:
1. Evaluate `viewer` sub-expression
2. Evaluate `editor` sub-expression
3. Return **Allow** if ANY evaluates to Allow (union semantics)

### Tuple-to-Userset Evaluation

When evaluating `viewer from parent`:
1. Query tuples for `<resource>#parent@*` (find parents)
2. For each parent resource:
   - Recursively check if user has `viewer` on parent
3. Return **Allow** if ANY parent check returns Allow

### Cycle Detection

The evaluator detects cycles to prevent infinite loops:

```ipl
type folder {
    relation parent: folder
    relation viewer = viewer from parent  // Could cycle
}
```

If `folder:a#parent@folder:b` and `folder:b#parent@folder:a`, the evaluator detects the cycle and returns **Deny**.

## Best Practices

### 1. Use Clear Naming

```ipl
// Good
relation can_view = viewer | editor
relation can_edit = editor
relation can_delete = owner

// Avoid
relation r1 = r2 | r3
```

### 2. Minimize Indirection

Deeply nested tuple-to-userset chains impact performance:

```ipl
// Moderate indirection (good)
relation can_view = viewer | viewer from parent

// Deep indirection (avoid if possible)
relation can_view = viewer from parent from parent from parent
```

### 3. Use Intersection Sparingly

Intersection requires checking ALL conditions, making it slower:

```ipl
// Prefer union (faster)
relation can_view = viewer | editor

// Use intersection only when necessary
relation can_view_sensitive = viewer & clearance
```

### 4. Leverage the Cache

Frequently checked permissions benefit from caching. Structure your schema so common checks hit the cache:

```ipl
// Common check - will be cached
relation can_view = viewer | editor | owner

// Less common check
relation can_view_during_hours = can_view & module("business_hours")
```

### 5. Document Complex Relations

```ipl
type document {
    relation viewer
    relation editor
    relation org: organization

    // Allow view if:
    // 1. Direct viewer/editor on document
    // 2. Member of document's organization
    relation can_view = viewer | editor | member from org
}
```

## Validation Rules

The IPL parser enforces several validation rules:

1. **Type references must exist**: `relation parent: folder` requires `folder` type to be defined
2. **Relation references must exist**: `viewer from parent` requires both `viewer` and `parent` to be defined
3. **No duplicate relations**: Each relation name must be unique within a type
4. **No duplicate types**: Each type name must be unique in the schema

## Performance Considerations

### Query Cost Estimation

The query optimizer assigns costs to different relation types:

- **Direct lookup** (`this`): Cost 1
- **Relation reference**: Cost 5 (requires recursion)
- **Tuple-to-userset**: Cost 10 (requires multiple lookups)
- **WASM module**: Cost 8 (requires module execution)

Union of expensive operations suggests caching:

```ipl
// High cost - optimizer will suggest caching
relation can_view =
    viewer from parent from parent |
    editor from org |
    module("custom_check")
```

### Parallelization

Union and intersection branches can be evaluated in parallel:

```ipl
// These can be evaluated concurrently
relation can_view = viewer | editor | owner | member from org
```

The parallel evaluator spawns tasks for each branch and aggregates results.

## Error Handling

IPL parsing errors include:

- **Syntax errors**: Invalid grammar
- **Semantic errors**: Undefined type/relation references
- **Circular references**: Detected at evaluation time

Example error:

```
Parse error: Undefined relation 'nonexistent' in type 'document'
  at line 5, column 23
```

## Migration Guide

When updating IPL schemas:

1. **Add new relations** - Safe, backward compatible
2. **Remove relations** - May break existing checks
3. **Change relation semantics** - Requires careful testing
4. **Invalidate cache** - After schema changes

## Examples Library

See the [examples](../examples/) directory for complete IPL schemas:

- `document-management.ipl` - Document/folder hierarchy
- `organization-hierarchy.ipl` - Multi-tenant organizations
- `github-like.ipl` - GitHub-style repository permissions
- `google-drive.ipl` - Google Drive-like sharing
