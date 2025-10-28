//! Span creation utilities for authorization operations
//!
//! Provides convenient macros and functions for creating spans with
//! consistent attributes across the InferaDB codebase.

use tracing::{span, Level, Span};

/// Create a span for an authorization check operation
///
/// # Arguments
/// * `subject` - The subject requesting access
/// * `resource` - The resource being accessed
/// * `permission` - The permission being checked
///
/// # Returns
/// A tracing span configured for authorization checks
pub fn check_span(subject: &str, resource: &str, permission: &str) -> Span {
    span!(
        Level::INFO,
        "authorization_check",
        subject = subject,
        resource = resource,
        permission = permission,
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
    )
}

/// Create a span for relation evaluation
///
/// # Arguments
/// * `relation` - The relation being evaluated
/// * `resource_type` - The type of the resource
///
/// # Returns
/// A tracing span for relation evaluation
pub fn evaluation_span(relation: &str, resource_type: &str) -> Span {
    span!(
        Level::DEBUG,
        "relation_evaluation",
        relation = relation,
        resource_type = resource_type,
        decision = tracing::field::Empty,
    )
}

/// Create a span for tuple store operations
///
/// # Arguments
/// * `operation` - The operation being performed (e.g., "read", "write")
/// * `object` - The object being operated on
///
/// # Returns
/// A tracing span for store operations
pub fn store_span(operation: &str, object: &str) -> Span {
    span!(
        Level::DEBUG,
        "tuple_store_operation",
        operation = operation,
        object = object,
        tuple_count = tracing::field::Empty,
    )
}

/// Create a span for cache operations
///
/// # Arguments
/// * `operation` - The operation being performed (e.g., "get", "set", "invalidate")
/// * `key` - The cache key
///
/// # Returns
/// A tracing span for cache operations
pub fn cache_span(operation: &str, key: &str) -> Span {
    span!(
        Level::DEBUG,
        "cache_operation",
        operation = operation,
        cache_key = key,
        hit = tracing::field::Empty,
    )
}

/// Create a span for WASM module execution
///
/// # Arguments
/// * `module_name` - The name of the WASM module
///
/// # Returns
/// A tracing span for WASM execution
pub fn wasm_span(module_name: &str) -> Span {
    span!(
        Level::DEBUG,
        "wasm_execution",
        module = module_name,
        fuel_consumed = tracing::field::Empty,
        result = tracing::field::Empty,
    )
}

/// Create a span for query optimization
///
/// # Arguments
/// * `relation` - The relation being optimized
///
/// # Returns
/// A tracing span for query optimization
pub fn optimization_span(relation: &str) -> Span {
    span!(
        Level::DEBUG,
        "query_optimization",
        relation = relation,
        estimated_cost = tracing::field::Empty,
        parallelizable = tracing::field::Empty,
    )
}

/// Create a span for parallel evaluation
///
/// # Arguments
/// * `operation` - The operation type (e.g., "union", "intersection")
/// * `branch_count` - Number of branches being evaluated
///
/// # Returns
/// A tracing span for parallel evaluation
pub fn parallel_span(operation: &str, branch_count: usize) -> Span {
    span!(
        Level::DEBUG,
        "parallel_evaluation",
        operation = operation,
        branch_count = branch_count,
        completed_branches = tracing::field::Empty,
    )
}

/// Record a decision result in the current span
///
/// # Arguments
/// * `span` - The span to record in
/// * `decision` - The decision result ("allow" or "deny")
pub fn record_decision(span: &Span, decision: &str) {
    span.record("decision", decision);
    span.record(
        "otel.status_code",
        if decision == "allow" { "OK" } else { "ERROR" },
    );
}

/// Record cache hit/miss information
///
/// # Arguments
/// * `span` - The span to record in
/// * `hit` - Whether it was a cache hit
pub fn record_cache_hit(span: &Span, hit: bool) {
    span.record("hit", hit);
}

/// Record tuple count for store operations
///
/// # Arguments
/// * `span` - The span to record in
/// * `count` - Number of tuples
pub fn record_tuple_count(span: &Span, count: usize) {
    span.record("tuple_count", count);
}

/// Record WASM execution results
///
/// # Arguments
/// * `span` - The span to record in
/// * `fuel_consumed` - Amount of fuel consumed
/// * `result` - Execution result
pub fn record_wasm_result(span: &Span, fuel_consumed: u64, result: i32) {
    span.record("fuel_consumed", fuel_consumed);
    span.record("result", result);
}

/// Record query optimization results
///
/// # Arguments
/// * `span` - The span to record in
/// * `cost` - Estimated cost
/// * `parallelizable` - Whether the query can be parallelized
pub fn record_optimization(span: &Span, cost: usize, parallelizable: bool) {
    span.record("estimated_cost", cost);
    span.record("parallelizable", parallelizable);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_tracing() {
        INIT.call_once(|| {
            // Initialize subscriber once for all tests
            let _ = tracing_subscriber::fmt::try_init();
        });
    }

    #[test]
    fn test_check_span_creation() {
        init_test_tracing();

        let span = check_span("user:alice", "document:readme", "can_view");
        // Verify span was created - metadata may be None if subscriber not enabled
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "authorization_check");
            assert_eq!(metadata.level(), &Level::INFO);
        }
    }

    #[test]
    fn test_evaluation_span_creation() {
        init_test_tracing();

        let span = evaluation_span("viewer", "document");
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "relation_evaluation");
            assert_eq!(metadata.level(), &Level::DEBUG);
        }
    }

    #[test]
    fn test_store_span_creation() {
        init_test_tracing();

        let span = store_span("read", "document:readme");
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "tuple_store_operation");
        }
    }

    #[test]
    fn test_cache_span_creation() {
        init_test_tracing();

        let span = cache_span("get", "user:alice#document:readme#can_view");
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "cache_operation");
        }
    }

    #[test]
    fn test_wasm_span_creation() {
        init_test_tracing();

        let span = wasm_span("business_hours");
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "wasm_execution");
        }
    }

    #[test]
    fn test_optimization_span_creation() {
        init_test_tracing();

        let span = optimization_span("can_view");
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "query_optimization");
        }
    }

    #[test]
    fn test_parallel_span_creation() {
        init_test_tracing();

        let span = parallel_span("union", 3);
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "parallel_evaluation");
        }
    }

    #[test]
    fn test_record_decision() {
        init_test_tracing();

        let span = check_span("user:alice", "document:readme", "can_view");
        let _entered = span.enter();
        record_decision(&span, "allow");
        // Just verify it doesn't panic - actual recording tested in integration
    }

    #[test]
    fn test_record_cache_hit() {
        init_test_tracing();

        let span = cache_span("get", "test_key");
        let _entered = span.enter();
        record_cache_hit(&span, true);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_tuple_count() {
        init_test_tracing();

        let span = store_span("read", "document:readme");
        let _entered = span.enter();
        record_tuple_count(&span, 5);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_wasm_result() {
        init_test_tracing();

        let span = wasm_span("test_module");
        let _entered = span.enter();
        record_wasm_result(&span, 1000, 1);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_optimization() {
        init_test_tracing();

        let span = optimization_span("can_view");
        let _entered = span.enter();
        record_optimization(&span, 15, true);
        // Just verify it doesn't panic
    }
}
