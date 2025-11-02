//! Structured logging utilities for InferaDB
//!
//! Provides enhanced logging with contextual fields and formatting options.

use tracing::Span;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

/// Log output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable format with colors (for development)
    Pretty,
    /// Compact format without colors
    Compact,
    /// JSON format (for production)
    Json,
}

#[allow(clippy::derivable_impls)]
impl Default for LogFormat {
    fn default() -> Self {
        #[cfg(debug_assertions)]
        {
            LogFormat::Pretty
        }
        #[cfg(not(debug_assertions))]
        {
            LogFormat::Json
        }
    }
}

/// Configuration for logging behavior
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Output format
    pub format: LogFormat,
    /// Whether to include file/line numbers
    pub include_location: bool,
    /// Whether to include target module
    pub include_target: bool,
    /// Whether to include thread IDs
    pub include_thread_id: bool,
    /// Whether to log span events (enter/exit/close)
    pub log_spans: bool,
    /// Environment filter (e.g., "info,infera=debug")
    pub filter: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            include_location: cfg!(debug_assertions),
            include_target: true,
            include_thread_id: false,
            log_spans: cfg!(debug_assertions),
            filter: None,
        }
    }
}

/// Initialize structured logging with configuration
///
/// This is a more flexible alternative to `init_tracing()` that allows
/// customization of log format and behavior.
pub fn init_logging(config: LogConfig) -> anyhow::Result<()> {
    let env_filter = if let Some(filter) = config.filter {
        EnvFilter::try_new(filter)?
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,infera=debug"))
    };

    let fmt_span = if config.log_spans {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(config.include_target)
        .with_thread_ids(config.include_thread_id)
        .with_file(config.include_location)
        .with_line_number(config.include_location)
        .with_span_events(fmt_span);

    match config.format {
        LogFormat::Pretty => {
            subscriber
                .pretty()
                .try_init()
                .map_err(|e| anyhow::anyhow!("Failed to initialize pretty logger: {}", e))?;
        }
        LogFormat::Compact => {
            subscriber
                .compact()
                .try_init()
                .map_err(|e| anyhow::anyhow!("Failed to initialize compact logger: {}", e))?;
        }
        LogFormat::Json => {
            subscriber
                .json()
                .try_init()
                .map_err(|e| anyhow::anyhow!("Failed to initialize JSON logger: {}", e))?;
        }
    }

    tracing::info!(
        format = ?config.format,
        location = config.include_location,
        target = config.include_target,
        "Logging initialized"
    );

    Ok(())
}

/// Helper to create a span with common authorization fields
pub fn auth_span(subject: &str, resource: &str, permission: &str) -> Span {
    tracing::info_span!(
        "authorization",
        subject = subject,
        resource = resource,
        permission = permission,
        decision = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    )
}

/// Helper to create a span for storage operations
pub fn storage_span(operation: &str, count: usize) -> Span {
    tracing::debug_span!(
        "storage",
        operation = operation,
        relationship_count = count,
        duration_ms = tracing::field::Empty,
    )
}

/// Helper to create a span for evaluation operations
pub fn eval_span(relation: &str, depth: usize) -> Span {
    tracing::debug_span!(
        "evaluation",
        relation = relation,
        depth = depth,
        branches = tracing::field::Empty,
        result = tracing::field::Empty,
    )
}

/// Helper to create a span for API requests
pub fn api_span(method: &str, path: &str) -> Span {
    tracing::info_span!(
        "api_request",
        http.method = method,
        http.route = path,
        http.status_code = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    )
}

/// Record decision in authorization span
pub fn record_auth_decision(span: &Span, decision: &str, duration_ms: u128) {
    span.record("decision", decision);
    span.record("duration_ms", duration_ms);
}

/// Record storage operation results
pub fn record_storage_result(span: &Span, duration_ms: u128) {
    span.record("duration_ms", duration_ms);
}

/// Record evaluation results
pub fn record_eval_result(span: &Span, branches: usize, result: bool) {
    span.record("branches", branches);
    span.record("result", result);
}

/// Record API request results
pub fn record_api_result(span: &Span, status_code: u16, duration_ms: u128) {
    span.record("http.status_code", status_code);
    span.record("duration_ms", duration_ms);
}

/// Log a slow query warning
pub fn log_slow_query(operation: &str, duration_ms: u128, threshold_ms: u128) {
    if duration_ms > threshold_ms {
        tracing::warn!(
            operation = operation,
            duration_ms = duration_ms,
            threshold_ms = threshold_ms,
            "Slow query detected"
        );
    }
}

/// Log an error with full context
pub fn log_error_with_context(
    error: &dyn std::error::Error,
    operation: &str,
    context: &[(&str, &dyn std::fmt::Display)],
) {
    tracing::error!(
        error = %error,
        operation = operation,
    );

    for (key, value) in context {
        tracing::error!(key = %key, value = %value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_logging() {
        INIT.call_once(|| {
            let _ = init_logging(LogConfig {
                format: LogFormat::Compact,
                include_location: false,
                include_target: false,
                include_thread_id: false,
                log_spans: true,
                filter: Some("debug".to_string()),
            });
        });
    }

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.format, LogFormat::default());
        assert!(config.include_target);
    }

    #[test]
    fn test_log_format_default() {
        let format = LogFormat::default();
        #[cfg(debug_assertions)]
        assert_eq!(format, LogFormat::Pretty);
        #[cfg(not(debug_assertions))]
        assert_eq!(format, LogFormat::Json);
    }

    #[test]
    fn test_init_logging_compact() {
        // Can't actually test initialization due to global state
        // but we can test configuration creation
        let config = LogConfig {
            format: LogFormat::Compact,
            include_location: false,
            include_target: true,
            include_thread_id: false,
            log_spans: false,
            filter: Some("debug".to_string()),
        };
        assert_eq!(config.format, LogFormat::Compact);
    }

    #[test]
    fn test_auth_span_creation() {
        init_test_logging();
        let span = auth_span("user:alice", "doc:readme", "can_view");
        assert!(span.metadata().is_some());
    }

    #[test]
    fn test_storage_span_creation() {
        init_test_logging();
        let span = storage_span("read", 10);
        assert!(span.metadata().is_some());
    }

    #[test]
    fn test_eval_span_creation() {
        init_test_logging();
        let span = eval_span("viewer", 3);
        assert!(span.metadata().is_some());
    }

    #[test]
    fn test_api_span_creation() {
        init_test_logging();
        let span = api_span("POST", "/check");
        assert!(span.metadata().is_some());
    }

    #[test]
    fn test_record_auth_decision() {
        init_test_logging();
        let span = auth_span("user:alice", "doc:readme", "can_view");
        let _entered = span.enter();
        record_auth_decision(&span, "allow", 5);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_storage_result() {
        init_test_logging();
        let span = storage_span("write", 5);
        let _entered = span.enter();
        record_storage_result(&span, 10);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_eval_result() {
        init_test_logging();
        let span = eval_span("viewer", 2);
        let _entered = span.enter();
        record_eval_result(&span, 3, true);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_record_api_result() {
        init_test_logging();
        let span = api_span("POST", "/check");
        let _entered = span.enter();
        record_api_result(&span, 200, 15);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_log_slow_query() {
        init_test_logging();
        log_slow_query("check", 150, 100);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_log_slow_query_below_threshold() {
        init_test_logging();
        log_slow_query("check", 50, 100);
        // Should not log, but shouldn't panic
    }

    #[test]
    fn test_log_error_with_context() {
        init_test_logging();
        let error = std::io::Error::new(std::io::ErrorKind::NotFound, "test error");
        log_error_with_context(
            &error,
            "read_relationship",
            &[("resource", &"doc:readme"), ("subject", &"alice")],
        );
        // Just verify it doesn't panic
    }
}
