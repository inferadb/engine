# Error Handling Standards

All error handling in InferaDB follows standardized patterns for consistency, maintainability, and proper error chain preservation.

## Core Requirements

Every error enum **MUST**:

1. **Use `thiserror::Error` derive**
2. **Have a Result type alias**: `pub type Result<T> = std::result::Result<T, MyError>;`
3. **Preserve error chains**: Use `#[from]` or `#[source]` to maintain error context

## Error Conversion Patterns

### Pattern 1: Automatic Conversion with `#[from]`

Use this when you want automatic `From` implementation and error chain preservation:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("Storage error")]
    Store(#[from] infera_types::StoreError),  // Auto-implements From<StoreError>
    
    #[error("IO error")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, MyError>;
```

### Pattern 2: Custom Conversion with Source Preservation

Use this when you need custom conversion logic but still want to preserve the error chain:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Authentication failed")]
    Auth {
        #[source]  // Preserves error chain for std::error::Error::source()
        source: infera_auth::AuthError,
    },
    
    #[error("Invalid input: {message}")]
    InvalidInput {
        message: String,
        #[source]
        source: serde_json::Error,
    },
}

impl From<infera_auth::AuthError> for ApiError {
    fn from(source: infera_auth::AuthError) -> Self {
        Self::Auth { source }
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
```

### Pattern 3: Internal Errors with anyhow (NOT for public APIs)

Use `anyhow` for internal error propagation where you need rich context but don't need structured error types:

```rust
use anyhow::{Context, Result};

async fn internal_operation() -> Result<Data> {
    let data = store.get_data()
        .await
        .context("Failed to retrieve data from store")?;
    
    process_data(&data)
        .context("Failed to process retrieved data")?;
    
    Ok(data)
}
```

**⚠️ Important:** Convert `anyhow::Error` to public error types at crate boundaries.

## Error Handling Guidelines

### 1. At Crate Boundaries

Convert to the crate's public error type:

```rust
// Public API
pub async fn public_function() -> Result<Data> {
    internal_operation()
        .await
        .map_err(|e| MyError::Internal { source: e.into() })
}

// Internal implementation
async fn internal_operation() -> anyhow::Result<Data> {
    // ... complex logic with anyhow
}
```

### 2. Within Crates

Use Result type alias for cleaner signatures:

```rust
// ❌ Verbose
fn operation() -> std::result::Result<T, MyVeryLongErrorTypeName> { }

// ✅ Clean
pub type Result<T> = std::result::Result<T, MyError>;

fn operation() -> Result<T> { }
```

### 3. For Context

Use `.context()` with anyhow internally, structured variants externally:

```rust
// Internal
data.parse()
    .context("Failed to parse configuration file")?

// External/Public
#[error("Failed to parse configuration: {path}")]
ConfigParse {
    path: String,
    #[source]
    source: serde_yaml::Error,
}
```

### 4. For Aggregation

Wrap multiple errors in enum variants, don't stringify:

```rust
// ❌ BAD: Loses error chain
#[error("Database error: {0}")]
Database(String),

// ✅ GOOD: Preserves error chain
#[error("Database query failed")]
DatabaseQuery {
    #[source]
    source: sqlx::Error,
},

#[error("Database connection failed")]
DatabaseConnection {
    #[source]
    source: sqlx::Error,
},
```

### 5. For Testing

Match on error variants, not error message strings:

```rust
// ❌ BAD: Fragile, breaks if message changes
assert_eq!(err.to_string(), "Entity not found");

// ✅ GOOD: Robust, tests actual error type
assert!(matches!(err, StorageError::NotFound { .. }));

// ✅ EVEN BETTER: Test specific fields
match err {
    StorageError::NotFound { entity_type, entity_id } => {
        assert_eq!(entity_type, "vault");
        assert_eq!(entity_id, "123");
    }
    _ => panic!("Expected NotFound error"),
}
```

## Anti-Patterns to Avoid

### ❌ Stringifying Errors

**Don't do this:**
```rust
.map_err(|e| MyError::Internal(e.to_string()))  // Loses error chain!
```

**Do this instead:**
```rust
.map_err(|e| MyError::Internal { source: e })?
// or use #[from] for automatic conversion
```

### ❌ Generic String Variants

**Don't do this:**
```rust
#[error("Internal error: {0}")]
Internal(String),  // Too generic, no structure, no source
```

**Do this instead:**
```rust
#[error("Internal operation failed: {operation}")]
InternalOperation {
    operation: String,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}
```

### ❌ No Result Type Alias

**Don't do this:**
```rust
fn operation() -> std::result::Result<T, MyVeryLongErrorTypeName>
```

**Do this instead:**
```rust
pub type Result<T> = std::result::Result<T, MyError>;

fn operation() -> Result<T>  // Clean and concise
```

### ❌ Missing Error Chains

**Don't do this:**
```rust
#[error("Failed to connect")]
Connection(String),  // No #[from] or #[source], chain broken
```

**Do this instead:**
```rust
#[error("Failed to connect")]
Connection(#[from] std::io::Error),  // Chain preserved
```

## Complete Example

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Entity not found: {entity_type}:{entity_id}")]
    NotFound {
        entity_type: String,
        entity_id: String,
    },

    #[error("Database error during {operation}")]
    Database {
        operation: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Serialization failed")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid input: {message}")]
    InvalidInput {
        message: String,
    },
}

pub type Result<T> = std::result::Result<T, StorageError>;

// Usage
async fn get_entity(id: &str) -> Result<Entity> {
    let data = database.query(id)
        .await
        .map_err(|e| StorageError::Database {
            operation: "query".to_string(),
            source: Box::new(e),
        })?;

    if data.is_empty() {
        return Err(StorageError::NotFound {
            entity_type: "entity".to_string(),
            entity_id: id.to_string(),
        });
    }

    // Automatic conversion via #[from]
    let entity: Entity = serde_json::from_str(&data)?;
    
    Ok(entity)
}
```

## Testing Error Handling

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_not_found_error() {
        let result = get_entity("nonexistent").await;

        // Test error variant
        assert!(matches!(result, Err(StorageError::NotFound { .. })));

        // Test specific fields
        if let Err(StorageError::NotFound { entity_type, entity_id }) = result {
            assert_eq!(entity_type, "entity");
            assert_eq!(entity_id, "nonexistent");
        }
    }

    #[tokio::test]
    async fn test_error_chain() {
        let result = get_entity("invalid").await;

        // Error chain preserved
        if let Err(e) = result {
            assert!(e.source().is_some(), "Error should have a source");
        }
    }
}
```

## Error Message Guidelines

1. **Be specific**: "Failed to parse configuration file" not "Parse error"
2. **Include context**: "Database query failed for user_id: 123" not "Query failed"
3. **Use active voice**: "Failed to connect" not "Connection failure"
4. **Avoid jargon**: "Network unreachable" not "ENETUNREACH"
5. **Suggest fixes when possible**: "File not found: ./config.yaml (create file or set CONFIG_PATH)"

## Related Documentation

- [Rust Error Handling](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
- [thiserror Documentation](https://docs.rs/thiserror/)
- [anyhow Documentation](https://docs.rs/anyhow/)

---

Last updated: 2025-11-03
