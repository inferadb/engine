# Type Organization and Centralization

This document explains how types are organized across InferaDB crates to prevent circular dependencies and maintain clean architecture.

## The infera-types Crate

The `infera-types` crate serves as the **single source of truth** for all shared type definitions. It has **zero dependencies** on other internal crates to prevent circular dependencies.

## Deciding Where Types Belong

### Types Belong in infera-types If:

- Used by multiple crates
- Core domain concepts (Relationship, Vault, Account, Decision, etc.)
- Request/response types for APIs
- Shared authentication types (AuthContext, AuthMethod)
- Common error types used across crate boundaries

### Types Should Stay in Their Implementation Crate If:

- Implementation-specific (e.g., AuthError with JWKS/OAuth details)
- Only used within a single crate
- Tied to a specific runtime or library (e.g., WASM types)
- Configuration types (belong in infera-config)

## Current infera-types Organization

```
crates/infera-types/src/
├── lib.rs          - Main exports
├── account.rs      - Account multi-tenancy type
├── vault.rs        - Vault and SystemConfig
└── auth.rs         - AuthContext and AuthMethod
```

## Layered Architecture

Types flow **downward only** through these layers:

```
Layer 0 (Foundation):  infera-types, infera-const
Layer 1 (Utilities):   infera-config, infera-observe
Layer 2 (Storage):     infera-store, infera-cache
Layer 3 (Runtime):     infera-wasm, infera-core, infera-auth
Layer 4 (Application): infera-repl, infera-api
Layer 5 (Binary):      infera-bin
```

**Rules:**

- Dependencies flow **downward only** (higher layers can depend on lower layers, never the reverse)
- `infera-types` **never** depends on other internal crates
- If a type is needed by multiple layers, it belongs in the **lowest common layer**
- When in doubt, put it in **infera-types**

## Adding New Types to infera-types

### Step-by-Step Process

1. Create a new module file (e.g., `src/mytype.rs`)
2. Define the type with appropriate derives (typically `Debug, Clone, Serialize, Deserialize`)
3. Add comprehensive doc comments
4. Include tests in the same file
5. Export from `lib.rs`:

```rust
// crates/infera-types/src/lib.rs
pub mod mytype;
pub use mytype::MyType;
```

### Example: Adding a New Type

```rust
// crates/infera-types/src/decision.rs
use serde::{Deserialize, Serialize};

/// Represents an authorization decision
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Access is granted
    Allow,
    /// Access is denied
    Deny,
}

impl Decision {
    /// Returns true if the decision is Allow
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Returns true if the decision is Deny
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_is_allow() {
        assert!(Decision::Allow.is_allow());
        assert!(!Decision::Deny.is_allow());
    }

    #[test]
    fn test_decision_is_deny() {
        assert!(Decision::Deny.is_deny());
        assert!(!Decision::Allow.is_deny());
    }
}
```

## Moving Types from Other Crates

Use the **re-export pattern** for backwards compatibility:

```rust
// OLD: crates/infera-some-crate/src/lib.rs
pub struct MyType { /* ... */ }

// NEW: crates/infera-types/src/mytype.rs
pub struct MyType { /* ... */ }

// NEW: crates/infera-some-crate/src/lib.rs
pub use infera_types::MyType;  // Re-export for backwards compatibility
```

**Benefits:**

- Zero breaking changes for consumers
- Clean migration path
- Maintains import compatibility

## Common Patterns

### 1. Serialization Attributes

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]  // For API compatibility
pub enum Decision {
    Allow,
    Deny,
}
```

### 2. Request/Response Pairs

```rust
pub struct CreateResourceRequest {
    pub name: String,
    pub owner: String,
}

pub struct CreateResourceResponse {
    pub id: String,
    pub created_at: i64,
}
```

### 3. Helper Constructors

```rust
impl DeleteFilter {
    pub fn exact(resource: String, relation: String, subject: String) -> Self {
        Self {
            resource: Some(resource),
            relation: Some(relation),
            subject: Some(subject),
        }
    }

    pub fn by_resource(resource: String) -> Self {
        Self {
            resource: Some(resource),
            relation: None,
            subject: None,
        }
    }
}
```

## Circular Dependency Prevention

### Layer Discipline

Layer violations (higher layers depending on lower layers, or circular dependencies) must be fixed immediately by:

1. Moving code to the appropriate layer
2. Refactoring to remove the dependency
3. Extracting shared types to a lower layer (typically infera-types)

### Example: Fixed Layer Violation

**Problem:** `infera-auth` (Layer 3) depended on `infera-store` (Layer 2) for vault validation.

**Solution:** Moved the database-dependent validation function (`validate_vault_access_with_store`) to `infera-api` (Layer 4), where it naturally belongs with other API-layer operations.

**Result:**
- `infera-auth` remains at Layer 3 with no storage dependencies
- Database-backed validation lives in `infera-api` at Layer 4
- Layering discipline maintained

## Migration Checklist

When moving a type to infera-types:

- [ ] Create module file in `crates/infera-types/src/`
- [ ] Move type definition with all derives and attributes
- [ ] Move all impl blocks and methods
- [ ] Move all tests
- [ ] Add module declaration to `lib.rs`
- [ ] Add public re-export to `lib.rs`
- [ ] Replace original with re-export
- [ ] Add infera-types dependency if needed
- [ ] Run `cargo test -p infera-types`
- [ ] Run `cargo test` on affected crates
- [ ] Run `cargo test --workspace`
- [ ] Run `cargo +nightly fmt --all`
- [ ] Run `cargo clippy --workspace -- -D warnings`

## Examples

### Good: Type in infera-types

```rust
// Used by infera-api, infera-auth, tests
pub struct AuthContext {
    pub vault: Uuid,
    pub account: Uuid,
    pub scopes: Vec<String>,
    // ...
}
```

### Good: Type Stays in Implementation Crate

```rust
// Only used within infera-auth, has impl-specific details
pub enum AuthError {
    JWKSFetchFailed(String),      // HTTP implementation detail
    TokenDecodeFailed(String),     // JWT library detail
    ReplayProtectionError(String), // Optional feature detail
}
```

## Future Improvements

Tracked in `PLAN.md`:

- Phase 3: Move cache key types to infera-types
- Phase 4: Reorganize lib.rs into feature-based modules
- Add cargo-deny to enforce dependency rules
- Add automated layer violation detection

## Related Documentation

- [Architecture Patterns](ARCHITECTURE.md)
- [Error Handling Standards](ERROR_HANDLING.md)
- [Cargo Workspace Structure](../Cargo.toml)

---

Last updated: 2025-11-03
