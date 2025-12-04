# Auditing

This guide covers integrating InferaDB's audit logging system into your application.

## Table of Contents

- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Event Types](#event-types)
- [Configuration](#configuration)
- [API Integration](#api-integration)
- [Testing](#testing)
- [Performance Considerations](#performance-considerations)

---

## Quick Start

### 1. Add Dependency

The audit module is part of `inferadb-observe`:

```toml
[dependencies]
inferadb-observe = { path = "../crates/inferadb-observe" }
```

### 2. Initialize Audit Logger

```rust
use inferadb_observe::audit::{AuditLogger, AuditConfig};

// Use default configuration (everything enabled)
let audit_logger = AuditLogger::default();

// Or customize
let config = AuditConfig {
    enabled: true,
    log_authorization_checks: true,
    log_relationship_writes: true,
    log_relationship_deletes: true,
    log_resource_lists: true,
    log_subject_lists: true,
    log_expand: true,
    log_simulations: true,
    sample_rate: 1.0, // 100% coverage
};

let audit_logger = AuditLogger::new(config);
```

### 3. Log Your First Event

```rust
use inferadb_observe::audit::*;

// Create metadata
let metadata = AuditMetadata {
    event_id: AuditEvent::generate_event_id(),
    timestamp: AuditEvent::current_timestamp(),
    event_type: AuditEventType::AuthorizationCheck,
    actor: "user:alice".to_string(),
    client_ip: Some("192.168.1.100".to_string()),
    user_agent: Some("MyApp/1.0".to_string()),
    request_id: Some("req-123".to_string()),
    tenant_id: None,
};

// Create event details
let details = AuditEventDetails::AuthorizationCheck(
    AuthorizationCheckDetails {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        decision: Decision::Allow,
        duration_ms: 5,
        context: None,
        relationships_evaluated: Some(3),
        traced: Some(false),
    }
);

// Log it
let event = AuditEvent::new(metadata, details);
audit_logger.log(event);
```

---

## Core Concepts

### Event Structure

Every audit event has two parts:

1. **Metadata**: Common fields across all events
   - `event_id`: Globally unique identifier
   - `timestamp`: RFC3339 timestamp
   - `event_type`: Type of operation
   - `actor`: User performing the action
   - `client_ip`: Source IP (optional)
   - `user_agent`: Client identifier (optional)
   - `request_id`: For correlation (optional)
   - `tenant_id`: For multi-tenancy (optional)

2. **Details**: Event-specific information
   - Tagged union based on event type
   - Contains operation parameters and results

### Logging Target

All audit events are logged to the `inferadb_audit` tracing target:

```rust
info!(target: "inferadb_audit", "{}", json);
```

This allows you to:

- Route audit logs separately from application logs
- Ship to dedicated SIEM systems
- Apply different retention policies

### Metrics

Three metrics track audit health:

```promql
# Total events logged
inferadb_audit_events_total{event_type="authorization_check"}

# Events sampled (dropped)
inferadb_audit_events_sampled_total{event_type="authorization_check"}

# Logging errors
inferadb_audit_events_errors_total{error_type="serialization_error"}
```

---

## Event Types

### 1. Authorization Check

Logs every authorization decision:

```rust
let details = AuditEventDetails::AuthorizationCheck(
    AuthorizationCheckDetails {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        decision: Decision::Allow, // or Decision::Deny
        duration_ms: 5,
        context: Some(serde_json::json!({
            "ip_address": "192.168.1.100",
            "time_of_day": "business_hours"
        })),
        relationships_evaluated: Some(3),
        traced: Some(false),
    }
);
```

**When to use**: Every call to Check/Evaluate API

**Fields**:

- `subject`: Who is requesting access
- `resource`: What they're accessing
- `permission`: What action they want to perform
- `decision`: Allow or Deny
- `duration_ms`: How long evaluation took
- `context`: Optional context data (for WASM/ABAC)
- `relationships_evaluated`: Number of relationships checked
- `traced`: Whether detailed trace was enabled

### 2. Relationship Write

Logs relationship creation:

```rust
let details = AuditEventDetails::RelationshipWrite(
    RelationshipWriteDetails {
        count: relationships.len(),
        sample: relationships.iter().take(10).map(|r|
            RelationshipRecord {
                resource: r.resource.clone(),
                relation: r.relation.clone(),
                subject: r.subject.clone(),
            }
        ).collect(),
        revision: Some("rev-123".to_string()),
    }
);
```

**When to use**: Every WriteRelationships API call

**Fields**:

- `count`: Total relationships written
- `sample`: First 10 relationships (for brevity)
- `revision`: Storage revision after write

**Note**: Only logs first 10 relationships to avoid huge audit logs. Full details are in storage.

### 3. Relationship Delete

Logs relationship deletion:

```rust
let details = AuditEventDetails::RelationshipDelete(
    RelationshipDeleteDetails {
        count: deleted_count,
        sample: Some(deleted_sample),
        filter: Some(DeleteFilterRecord {
            resource: Some("document:old-doc".to_string()),
            relation: None,
            subject: None,
        }),
        revision: Some("rev-124".to_string()),
    }
);
```

**When to use**: Every DeleteRelationships API call

**Fields**:

- `count`: Total relationships deleted
- `sample`: Sample deleted relationships
- `filter`: Delete filter used (if applicable)
- `revision`: Storage revision after delete

### 4. Resource List

Logs ListResources operations:

```rust
let details = AuditEventDetails::ResourceList(
    ResourceListDetails {
        subject: "user:alice".to_string(),
        resource_type: "document".to_string(),
        permission: "viewer".to_string(),
        result_count: 42,
        paginated: Some(true),
    }
);
```

**When to use**: Every ListResources API call

**Fields**:

- `subject`: Who is listing resources
- `resource_type`: Type filter applied
- `permission`: Permission checked
- `result_count`: How many resources returned
- `paginated`: Whether results were paginated

### 5. Subject List

Logs ListSubjects operations:

```rust
let details = AuditEventDetails::SubjectList(
    SubjectListDetails {
        resource: "document:readme".to_string(),
        relation: "viewer".to_string(),
        result_count: 15,
        subject_type: Some("user".to_string()),
    }
);
```

**When to use**: Every ListSubjects API call

**Fields**:

- `resource`: Resource being queried
- `relation`: Relation checked
- `result_count`: Number of subjects returned
- `subject_type`: Type filter (optional)

### 6. Expand

Logs Expand operations:

```rust
let details = AuditEventDetails::Expand(
    ExpandDetails {
        resource: "organization:acme".to_string(),
        relation: "member".to_string(),
        user_count: 150,
    }
);
```

**When to use**: Every Expand API call

**Fields**:

- `resource`: Resource expanded
- `relation`: Relation expanded
- `user_count`: Number of users in expanded set

### 7. Simulation

Logs what-if testing:

```rust
let details = AuditEventDetails::Simulation(
    SimulationDetails {
        subject: "user:test".to_string(),
        resource: "document:test".to_string(),
        permission: "viewer".to_string(),
        decision: Decision::Allow,
        context_relationship_count: 5,
    }
);
```

**When to use**: Every Simulate API call

**Fields**:

- `subject`: Subject in simulation
- `resource`: Resource in simulation
- `permission`: Permission checked
- `decision`: Simulated decision
- `context_relationship_count`: Ephemeral relationships used

---

## Configuration

### Production Configuration

For production, log everything with 100% coverage:

```rust
let config = AuditConfig {
    enabled: true,
    log_authorization_checks: true,
    log_relationship_writes: true,
    log_relationship_deletes: true,
    log_resource_lists: true,
    log_subject_lists: true,
    log_expand: true,
    log_simulations: true,
    sample_rate: 1.0, // 100% for compliance
};
```

### High-Volume Configuration

For very high-volume deployments, sample read operations:

```rust
let config = AuditConfig {
    enabled: true,
    // Always log mutations (required for compliance)
    log_relationship_writes: true,
    log_relationship_deletes: true,
    // Sample read operations
    log_authorization_checks: true,
    log_resource_lists: false, // Disable if not needed
    log_subject_lists: false,
    log_expand: false,
    log_simulations: true,
    sample_rate: 0.1, // Log 10% of events
};
```

**Important**: Never sample writes/deletes. Always use `sample_rate: 1.0` for mutations.

### Development Configuration

For development, you might want to disable audit logging:

```rust
let audit_logger = AuditLogger::disabled();
```

Or enable only specific events:

```rust
let config = AuditConfig {
    enabled: true,
    log_authorization_checks: true,
    log_relationship_writes: true,
    log_relationship_deletes: false,
    log_resource_lists: false,
    log_subject_lists: false,
    log_expand: false,
    log_simulations: false,
    sample_rate: 1.0,
};
```

---

## API Integration

### REST API Example

```rust
use axum::{extract::State, Json};
use inferadb_observe::audit::*;

struct AppState {
    audit_logger: Arc<AuditLogger>,
    // ... other state
}

async fn check_handler(
    State(state): State<AppState>,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>> {
    let start = std::time::Instant::now();

    // Perform authorization check
    let decision = state.evaluator.check(&request).await?;

    let duration_ms = start.elapsed().as_millis() as u64;

    // Create audit event
    let metadata = AuditMetadata {
        event_id: AuditEvent::generate_event_id(),
        timestamp: AuditEvent::current_timestamp(),
        event_type: AuditEventType::AuthorizationCheck,
        actor: extract_actor(&request),
        client_ip: extract_client_ip(&request),
        user_agent: extract_user_agent(&request),
        request_id: extract_request_id(&request),
        tenant_id: extract_tenant_id(&request),
    };

    let details = AuditEventDetails::AuthorizationCheck(
        AuthorizationCheckDetails {
            subject: request.subject.clone(),
            resource: request.resource.clone(),
            permission: request.permission.clone(),
            decision: if decision { Decision::Allow } else { Decision::Deny },
            duration_ms,
            context: request.context.clone(),
            relationships_evaluated: None, // Could track this
            traced: request.trace,
        }
    );

    // Log audit event
    state.audit_logger.log(AuditEvent::new(metadata, details));

    Ok(Json(CheckResponse { decision }))
}
```

### gRPC API Example

```rust
use tonic::{Request, Response, Status};
use inferadb_observe::audit::*;

impl InferaService for MyService {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let start = std::time::Instant::now();
        let req = request.into_inner();

        // Perform evaluation
        let decision = self.evaluator.check(&req).await
            .map_err(|e| Status::internal(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        // Extract metadata from gRPC request
        let metadata_map = request.metadata();

        let audit_metadata = AuditMetadata {
            event_id: AuditEvent::generate_event_id(),
            timestamp: AuditEvent::current_timestamp(),
            event_type: AuditEventType::AuthorizationCheck,
            actor: req.subject.clone(),
            client_ip: metadata_map.get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            user_agent: metadata_map.get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            request_id: metadata_map.get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            tenant_id: None,
        };

        let details = AuditEventDetails::AuthorizationCheck(
            AuthorizationCheckDetails {
                subject: req.subject,
                resource: req.resource,
                permission: req.permission,
                decision: if decision { Decision::Allow } else { Decision::Deny },
                duration_ms,
                context: req.context.and_then(|c| serde_json::from_str(&c).ok()),
                relationships_evaluated: None,
                traced: req.trace,
            }
        );

        self.audit_logger.log(AuditEvent::new(audit_metadata, details));

        Ok(Response::new(EvaluateResponse {
            decision: decision as i32
        }))
    }
}
```

### Helper Functions

Create helper functions to extract common metadata:

```rust
/// Extract actor from request
fn extract_actor(request: &HttpRequest) -> String {
    // From authentication context
    request.extensions()
        .get::<AuthContext>()
        .map(|ctx| ctx.user_id.clone())
        .unwrap_or_else(|| "anonymous".to_string())
}

/// Extract client IP
fn extract_client_ip(request: &HttpRequest) -> Option<String> {
    request.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            request.peer_addr()
                .map(|addr| addr.ip().to_string())
        })
}

/// Extract user agent
fn extract_user_agent(request: &HttpRequest) -> Option<String> {
    request.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Extract or generate request ID
fn extract_request_id(request: &HttpRequest) -> Option<String> {
    request.headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Extract tenant ID
fn extract_tenant_id(request: &HttpRequest) -> Option<String> {
    request.extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.tenant_id.clone())
}
```

---

## Testing

### Unit Testing

Test audit event creation:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_check_event() {
        let metadata = AuditMetadata {
            event_id: AuditEvent::generate_event_id(),
            timestamp: AuditEvent::current_timestamp(),
            event_type: AuditEventType::AuthorizationCheck,
            actor: "user:test".to_string(),
            client_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("Test/1.0".to_string()),
            request_id: Some("test-req".to_string()),
            tenant_id: None,
        };

        let details = AuditEventDetails::AuthorizationCheck(
            AuthorizationCheckDetails {
                subject: "user:alice".to_string(),
                resource: "doc:readme".to_string(),
                permission: "viewer".to_string(),
                decision: Decision::Allow,
                duration_ms: 5,
                context: None,
                relationships_evaluated: Some(3),
                traced: Some(false),
            }
        );

        let event = AuditEvent::new(metadata, details);

        // Verify serialization
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("user:alice"));
        assert!(json.contains("authorization_check"));

        // Verify deserialization
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.metadata.actor, "user:test");
    }

    #[test]
    fn test_audit_logger_disabled() {
        let logger = AuditLogger::disabled();
        assert!(!logger.is_enabled());

        // Logging should be no-op
        let event = create_test_event();
        logger.log(event); // Should not panic
    }

    #[test]
    fn test_sampling() {
        let config = AuditConfig {
            enabled: true,
            sample_rate: 0.5, // 50% sampling
            ..Default::default()
        };

        let logger = AuditLogger::new(config);

        // Log many events
        for _ in 0..1000 {
            let event = create_test_event();
            logger.log(event);
        }

        // Roughly 500 should be logged (probabilistic)
        // Check metrics to verify
    }
}
```

### Integration Testing

Test audit logging in integration tests:

```rust
#[tokio::test]
async fn test_check_api_audit_logging() {
    // Setup test environment
    let audit_logger = Arc::new(AuditLogger::default());
    let app = create_test_app(audit_logger.clone()).await;

    // Make request
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/check")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"subject":"user:alice","resource":"doc:readme","permission":"viewer"}"#
                ))
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify audit event was logged
    // (Check logs or metrics in real implementation)
}
```

### Manual Testing

Use `tracing_subscriber` to see audit logs during development:

```rust
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

fn init_test_logging() {
    let filter = EnvFilter::new("info,inferadb_audit=debug");

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
        )
        .init();
}

#[tokio::main]
async fn main() {
    init_test_logging();

    let audit_logger = AuditLogger::default();

    // Create test event
    let event = create_authorization_check_event();

    // Should print JSON to console
    audit_logger.log(event);
}
```

---

## Performance Considerations

### Overhead Characteristics

Audit logging overhead by operation type:

| Operation          | Overhead        | Notes                             |
| ------------------ | --------------- | --------------------------------- |
| Event creation     | ~10-50 μs       | Struct allocation + ID generation |
| JSON serialization | ~50-200 μs      | Depends on event size             |
| Logging call       | ~10-50 μs       | Async, non-blocking               |
| **Total**          | **~100-300 μs** | <1% for typical 5ms operations    |

### Optimization Tips

#### 1. Use Sampling for High Volume

```rust
// Read operations: sample 10%
let config = AuditConfig {
    log_authorization_checks: true,
    sample_rate: 0.1,
    ..Default::default()
};
```

#### 2. Disable Verbose Events

```rust
// Disable list operations if not needed
let config = AuditConfig {
    log_resource_lists: false,
    log_subject_lists: false,
    ..Default::default()
};
```

#### 3. Lazy Event Creation

Only create events if logging is enabled:

```rust
if audit_logger.is_enabled() {
    let event = create_audit_event(/* ... */);
    audit_logger.log(event);
}
```

#### 4. Async Log Shipping

Use async log shipping to avoid blocking:

```rust
// Tracing infrastructure handles this automatically
info!(target: "inferadb_audit", "{}", json);
```

#### 5. Batch Metadata Extraction

Extract metadata once per request:

```rust
struct RequestContext {
    audit_metadata: AuditMetadata,
    // ... other fields
}

// Extract once
let ctx = RequestContext {
    audit_metadata: extract_audit_metadata(&request),
};

// Reuse for multiple events in same request
audit_logger.log(create_event_1(ctx.audit_metadata.clone()));
audit_logger.log(create_event_2(ctx.audit_metadata.clone()));
```

### Benchmarking

Benchmark audit logging overhead:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_audit_logging(c: &mut Criterion) {
    let logger = AuditLogger::default();

    c.bench_function("create_authorization_event", |b| {
        b.iter(|| {
            let event = create_authorization_check_event();
            black_box(event);
        });
    });

    c.bench_function("log_authorization_event", |b| {
        b.iter(|| {
            let event = create_authorization_check_event();
            logger.log(black_box(event));
        });
    });
}

criterion_group!(benches, benchmark_audit_logging);
criterion_main!(benches);
```

---

## Best Practices

### 1. Always Log Mutations

Never disable or sample writes/deletes:

```rust
✅ GOOD
let config = AuditConfig {
    log_relationship_writes: true,
    log_relationship_deletes: true,
    sample_rate: 1.0,
    ..Default::default()
};

❌ BAD
let config = AuditConfig {
    log_relationship_writes: false, // Never disable!
    sample_rate: 0.1, // Never sample mutations!
    ..Default::default()
};
```

### 2. Include Request Context

Always provide request ID for correlation:

```rust
✅ GOOD
let metadata = AuditMetadata {
    request_id: Some(extract_request_id(&request)),
    // ...
};

❌ BAD
let metadata = AuditMetadata {
    request_id: None, // Missing correlation!
    // ...
};
```

### 3. Extract Real Client IP

Use X-Forwarded-For behind load balancers:

```rust
✅ GOOD
fn extract_client_ip(request: &HttpRequest) -> Option<String> {
    request.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
}

❌ BAD
fn extract_client_ip(request: &HttpRequest) -> Option<String> {
    // Returns load balancer IP, not client IP
    request.peer_addr().map(|addr| addr.ip().to_string())
}
```

### 4. Log Asynchronously

Never block on audit logging:

```rust
✅ GOOD
audit_logger.log(event); // Async via tracing

❌ BAD
audit_logger.log_sync(event).await?; // Would block!
```

### 5. Test Audit Coverage

Ensure all operations are audited:

```rust
#[tokio::test]
async fn test_all_operations_audited() {
    // Test each API endpoint generates audit event
    test_check_audited().await;
    test_write_audited().await;
    test_delete_audited().await;
    test_list_resources_audited().await;
    test_list_subjects_audited().await;
    test_expand_audited().await;
    test_simulate_audited().await;
}
```

---

## Troubleshooting

### Audit Logs Not Appearing

**Problem**: No audit logs in output

**Solution**:

1. Check logger is enabled:

   ```rust
   assert!(audit_logger.is_enabled());
   ```

2. Check tracing filter includes `inferadb_audit`:

   ```rust
   EnvFilter::new("info,inferadb_audit=info")
   ```

3. Check sampling rate:

   ```rust
   config.sample_rate = 1.0; // Temporarily set to 100%
   ```

### High Memory Usage

**Problem**: Audit logging consuming too much memory

**Solution**:

1. Increase sample rate (reduce logging):

   ```rust
   config.sample_rate = 0.1; // 10% sampling
   ```

2. Disable verbose events:

   ```rust
   config.log_resource_lists = false;
   config.log_subject_lists = false;
   ```

3. Use async log shipping with batching

### JSON Serialization Errors

**Problem**: Audit events failing to serialize

**Solution**:

1. Check context data is valid JSON:

   ```rust
   let context = serde_json::from_str(&context_str)?;
   ```

2. Verify all strings are valid UTF-8

3. Check metrics for serialization errors:

   ```promql
   inferadb_audit_events_errors_total{error_type="serialization_error"}
   ```

---

## References

- [Audit Module Source](../crates/inferadb-observe/src/audit.rs)
- [SIEM Integration Guide](../AUDIT_LOGGING.md)
- [Metrics Reference](../grafana/METRICS_REFERENCE.md)
- [API Examples](../examples/audit-integration/)

---

## Support

For audit logging issues:

1. Check this documentation
2. Review audit event schemas
3. Test with sample events
4. Check tracing configuration
5. Open an issue if problems persist
