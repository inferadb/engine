//! Log aggregation integrations for centralized logging systems
//!
//! Provides adapters for popular log aggregation platforms including
//! Elasticsearch, Loki, and AWS CloudWatch.

use anyhow::Result;
use serde_json::json;
use tokio::sync::mpsc;
use tracing::Subscriber;
use tracing_subscriber::{Layer, Registry};

/// Log aggregation backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationBackend {
    /// Elasticsearch backend
    Elasticsearch,
    /// Grafana Loki backend
    Loki,
    /// AWS CloudWatch backend
    CloudWatch,
}

/// Configuration for log aggregation
#[derive(Debug, Clone)]
pub struct AggregationConfig {
    /// Backend type
    pub backend: AggregationBackend,
    /// Endpoint URL
    pub endpoint: String,
    /// Optional authentication token
    pub auth_token: Option<String>,
    /// Buffer size for batching logs
    pub buffer_size: usize,
    /// Flush interval in seconds
    pub flush_interval_secs: u64,
    /// Additional labels/tags for all logs
    pub labels: Vec<(String, String)>,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            backend: AggregationBackend::Loki,
            endpoint: "http://localhost:3100".to_string(),
            auth_token: None,
            buffer_size: 1000,
            flush_interval_secs: 5,
            labels: vec![
                ("service".to_string(), "inferadb".to_string()),
                ("environment".to_string(), "production".to_string()),
            ],
        }
    }
}

/// Log entry for batching and sending
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Timestamp in nanoseconds
    pub timestamp_ns: i64,
    /// Log level
    pub level: String,
    /// Log message
    pub message: String,
    /// Structured fields
    pub fields: serde_json::Value,
}

/// Elasticsearch log shipper
#[derive(Clone)]
pub struct ElasticsearchShipper {
    endpoint: String,
    auth_token: Option<String>,
    client: reqwest::Client,
    index_prefix: String,
}

impl ElasticsearchShipper {
    /// Create a new Elasticsearch shipper
    pub fn new(config: &AggregationConfig) -> Self {
        Self {
            endpoint: config.endpoint.clone(),
            auth_token: config.auth_token.clone(),
            client: reqwest::Client::new(),
            index_prefix: "inferadb-logs".to_string(),
        }
    }

    /// Ship logs to Elasticsearch
    pub async fn ship(&self, entries: Vec<LogEntry>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        // Use bulk API for efficiency
        let mut bulk_body = String::new();

        for entry in entries {
            let index_name =
                format!("{}-{}", self.index_prefix, chrono::Utc::now().format("%Y.%m.%d"));

            // Index action
            let action = json!({
                "index": {
                    "_index": index_name,
                }
            });
            bulk_body.push_str(&serde_json::to_string(&action)?);
            bulk_body.push('\n');

            // Document
            let doc = json!({
                "@timestamp": chrono::DateTime::from_timestamp_nanos(entry.timestamp_ns).to_rfc3339(),
                "level": entry.level,
                "message": entry.message,
                "fields": entry.fields,
            });
            bulk_body.push_str(&serde_json::to_string(&doc)?);
            bulk_body.push('\n');
        }

        let url = format!("{}/_bulk", self.endpoint);
        let mut request = self.client.post(&url).header("Content-Type", "application/x-ndjson");

        if let Some(token) = &self.auth_token {
            request = request.bearer_auth(token);
        }

        let response = request.body(bulk_body).send().await?;

        if !response.status().is_success() {
            let body = response.text().await?;
            anyhow::bail!("Elasticsearch bulk insert failed: {}", body);
        }

        Ok(())
    }
}

/// Loki log shipper
#[derive(Clone)]
pub struct LokiShipper {
    endpoint: String,
    auth_token: Option<String>,
    client: reqwest::Client,
    labels: Vec<(String, String)>,
}

impl LokiShipper {
    /// Create a new Loki shipper
    pub fn new(config: &AggregationConfig) -> Self {
        Self {
            endpoint: config.endpoint.clone(),
            auth_token: config.auth_token.clone(),
            client: reqwest::Client::new(),
            labels: config.labels.clone(),
        }
    }

    /// Ship logs to Loki
    pub async fn ship(&self, entries: Vec<LogEntry>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        // Build labels
        let mut labels_str = String::new();
        for (i, (key, value)) in self.labels.iter().enumerate() {
            if i > 0 {
                labels_str.push(',');
            }
            labels_str.push_str(&format!("{}=\"{}\"", key, value));
        }

        // Convert entries to Loki format
        let values: Vec<[String; 2]> = entries
            .into_iter()
            .map(|entry| {
                // Timestamp as string (nanoseconds)
                let ts = entry.timestamp_ns.to_string();

                // Combine message with fields as JSON
                let log_line = json!({
                    "level": entry.level,
                    "message": entry.message,
                    "fields": entry.fields,
                });

                [ts, serde_json::to_string(&log_line).unwrap()]
            })
            .collect();

        let payload = json!({
            "streams": [
                {
                    "stream": {
                        "labels": labels_str.clone()
                    },
                    "values": values
                }
            ]
        });

        let url = format!("{}/loki/api/v1/push", self.endpoint);
        let mut request = self.client.post(&url).header("Content-Type", "application/json");

        if let Some(token) = &self.auth_token {
            request = request.header("X-Scope-OrgID", "inferadb").bearer_auth(token);
        }

        let response = request.json(&payload).send().await?;

        if !response.status().is_success() {
            let body = response.text().await?;
            anyhow::bail!("Loki push failed: {}", body);
        }

        Ok(())
    }
}

/// CloudWatch log shipper
#[derive(Clone)]
pub struct CloudWatchShipper {
    log_group_name: String,
    log_stream_name: String,
    region: String,
}

impl CloudWatchShipper {
    /// Create a new CloudWatch shipper
    pub fn new(config: &AggregationConfig) -> Self {
        // Parse endpoint to extract region
        // Format: cloudwatch:region:log-group:log-stream
        let parts: Vec<&str> = config.endpoint.split(':').collect();
        let region = parts.get(1).unwrap_or(&"us-east-1").to_string();
        let log_group = parts.get(2).unwrap_or(&"inferadb").to_string();
        let log_stream = parts.get(3).unwrap_or(&"inferadb-default").to_string();

        Self { log_group_name: log_group, log_stream_name: log_stream, region }
    }

    /// Ship logs to CloudWatch
    ///
    /// Note: This is a basic implementation that would require AWS SDK integration
    /// for production use. For now, it provides the structure and interface.
    pub async fn ship(&self, entries: Vec<LogEntry>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        // In a real implementation, this would use the AWS SDK:
        // - aws-config and aws-sdk-cloudwatchlogs crates
        // - Proper authentication via AWS credentials
        // - PutLogEvents API call with sequence token management

        tracing::debug!(
            log_group = %self.log_group_name,
            log_stream = %self.log_stream_name,
            region = %self.region,
            count = entries.len(),
            "CloudWatch shipper would send logs (AWS SDK required for actual implementation)"
        );

        // Placeholder: would call AWS SDK here
        // let config = aws_config::load_from_env().await;
        // let client = aws_sdk_cloudwatchlogs::Client::new(&config);
        // ...

        Ok(())
    }
}

/// Aggregation layer for tracing-subscriber
pub struct AggregationLayer {
    sender: mpsc::UnboundedSender<LogEntry>,
}

impl AggregationLayer {
    /// Create a new aggregation layer
    pub fn new(sender: mpsc::UnboundedSender<LogEntry>) -> Self {
        Self { sender }
    }
}

impl<S> Layer<S> for AggregationLayer
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();
        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);

        let entry = LogEntry {
            timestamp_ns,
            level: metadata.level().to_string(),
            message: visitor.message.unwrap_or_else(|| metadata.target().to_string()),
            fields: serde_json::Value::Object(visitor.fields),
        };

        // Send to background shipper (ignore errors if buffer full)
        let _ = self.sender.send(entry);
    }
}

/// Visitor to extract fields as JSON
#[derive(Default)]
struct JsonVisitor {
    message: Option<String>,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl tracing::field::Visit for JsonVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let value_str = format!("{:?}", value);

        if field.name() == "message" {
            self.message = Some(value_str);
        } else {
            self.fields.insert(field.name().to_string(), json!(value_str));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.insert(field.name().to_string(), json!(value));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
}

/// Background task that batches and ships logs
pub struct LogShipper {
    config: AggregationConfig,
    receiver: mpsc::UnboundedReceiver<LogEntry>,
}

impl LogShipper {
    /// Create a new log shipper
    pub fn new(config: AggregationConfig) -> (Self, mpsc::UnboundedSender<LogEntry>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { config, receiver }, sender)
    }

    /// Run the shipper background task
    pub async fn run(mut self) {
        let mut buffer = Vec::with_capacity(self.config.buffer_size);
        let flush_interval = tokio::time::Duration::from_secs(self.config.flush_interval_secs);
        let mut flush_timer = tokio::time::interval(flush_interval);

        loop {
            tokio::select! {
                // Receive log entries
                Some(entry) = self.receiver.recv() => {
                    buffer.push(entry);

                    // Flush if buffer is full
                    if buffer.len() >= self.config.buffer_size {
                        self.flush(&mut buffer).await;
                    }
                }

                // Periodic flush
                _ = flush_timer.tick() => {
                    if !buffer.is_empty() {
                        self.flush(&mut buffer).await;
                    }
                }
            }
        }
    }

    /// Flush buffered logs to the backend
    async fn flush(&self, buffer: &mut Vec<LogEntry>) {
        if buffer.is_empty() {
            return;
        }

        let entries = std::mem::take(buffer);

        let result = match self.config.backend {
            AggregationBackend::Elasticsearch => {
                let shipper = ElasticsearchShipper::new(&self.config);
                shipper.ship(entries).await
            },
            AggregationBackend::Loki => {
                let shipper = LokiShipper::new(&self.config);
                shipper.ship(entries).await
            },
            AggregationBackend::CloudWatch => {
                let shipper = CloudWatchShipper::new(&self.config);
                shipper.ship(entries).await
            },
        };

        if let Err(e) = result {
            tracing::error!(error = %e, backend = ?self.config.backend, "Failed to ship logs");
        }
    }
}

/// Initialize logging with aggregation support
pub fn init_with_aggregation(
    log_config: super::logging::LogConfig,
    aggregation_config: AggregationConfig,
) -> Result<tokio::task::JoinHandle<()>> {
    use tracing_subscriber::prelude::*;

    // Create shipper and get sender
    let (shipper, sender) = LogShipper::new(aggregation_config);

    // Create aggregation layer
    let aggregation_layer = AggregationLayer::new(sender);

    // Create base subscriber
    let env_filter = if let Some(filter) = log_config.filter {
        tracing_subscriber::EnvFilter::try_new(filter)?
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,infera=debug"))
    };

    // Combine layers
    let subscriber = Registry::default().with(env_filter).with(aggregation_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow::anyhow!("Failed to set global subscriber: {}", e))?;

    // Spawn background shipper task
    let handle = tokio::spawn(async move {
        shipper.run().await;
    });

    tracing::info!(
        backend = ?log_config.format,
        "Logging with aggregation initialized"
    );

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregation_config_default() {
        let config = AggregationConfig::default();
        assert_eq!(config.backend, AggregationBackend::Loki);
        assert_eq!(config.buffer_size, 1000);
        assert_eq!(config.flush_interval_secs, 5);
        assert!(!config.labels.is_empty());
    }

    #[test]
    fn test_elasticsearch_shipper_creation() {
        let config = AggregationConfig {
            backend: AggregationBackend::Elasticsearch,
            endpoint: "http://localhost:9200".to_string(),
            auth_token: Some("token123".to_string()),
            ..Default::default()
        };

        let shipper = ElasticsearchShipper::new(&config);
        assert_eq!(shipper.endpoint, "http://localhost:9200");
        assert_eq!(shipper.auth_token, Some("token123".to_string()));
    }

    #[test]
    fn test_loki_shipper_creation() {
        let config = AggregationConfig {
            backend: AggregationBackend::Loki,
            endpoint: "http://localhost:3100".to_string(),
            auth_token: None,
            labels: vec![("app".to_string(), "test".to_string())],
            ..Default::default()
        };

        let shipper = LokiShipper::new(&config);
        assert_eq!(shipper.endpoint, "http://localhost:3100");
        assert_eq!(shipper.labels.len(), 1);
    }

    #[test]
    fn test_cloudwatch_shipper_creation() {
        let config = AggregationConfig {
            backend: AggregationBackend::CloudWatch,
            endpoint: "cloudwatch:us-west-2:my-log-group:my-stream".to_string(),
            ..Default::default()
        };

        let shipper = CloudWatchShipper::new(&config);
        assert_eq!(shipper.region, "us-west-2");
        assert_eq!(shipper.log_group_name, "my-log-group");
        assert_eq!(shipper.log_stream_name, "my-stream");
    }

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry {
            timestamp_ns: 1234567890,
            level: "INFO".to_string(),
            message: "Test message".to_string(),
            fields: json!({"key": "value"}),
        };

        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.message, "Test message");
    }

    #[test]
    fn test_log_shipper_creation() {
        let config = AggregationConfig::default();
        let (shipper, _sender) = LogShipper::new(config.clone());

        // Verify shipper was created successfully
        assert_eq!(shipper.config.backend, config.backend);
    }

    #[tokio::test]
    async fn test_elasticsearch_ship_empty() {
        let config = AggregationConfig {
            backend: AggregationBackend::Elasticsearch,
            endpoint: "http://localhost:9200".to_string(),
            ..Default::default()
        };

        let shipper = ElasticsearchShipper::new(&config);
        let result = shipper.ship(vec![]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_loki_ship_empty() {
        let config = AggregationConfig::default();
        let shipper = LokiShipper::new(&config);
        let result = shipper.ship(vec![]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cloudwatch_ship_empty() {
        let config = AggregationConfig {
            backend: AggregationBackend::CloudWatch,
            endpoint: "cloudwatch:us-east-1:logs:stream".to_string(),
            ..Default::default()
        };

        let shipper = CloudWatchShipper::new(&config);
        let result = shipper.ship(vec![]).await;
        assert!(result.is_ok());
    }
}
