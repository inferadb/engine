//! # Audit Logging for InferaDB
//!
//! Provides comprehensive audit logging for all authorization decisions and relationship changes.
//! Audit events are structured, tamper-evident, and exportable to SIEM systems.

use std::{sync::Arc, time::SystemTime};

use inferadb_engine_types::Decision;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/// Audit event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Authorization check performed
    AuthorizationCheck,
    /// Relationship(s) written
    RelationshipWrite,
    /// Relationship(s) deleted
    RelationshipDelete,
    /// Resource listing performed
    ResourceList,
    /// Subject listing performed
    SubjectList,
    /// Relationship listing performed
    RelationshipList,
    /// Expand operation performed
    Expand,
    /// Watch stream started
    WatchStart,
    /// Simulation performed
    Simulation,
}

/// Audit event metadata
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct AuditMetadata {
    /// Unique event ID
    pub event_id: String,
    /// Event timestamp (RFC3339 format)
    pub timestamp: String,
    /// Event type
    pub event_type: AuditEventType,
    /// User/subject performing the action
    pub actor: String,
    /// Client IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// User agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Request ID for correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Tenant ID (for multi-tenant deployments)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

/// Authorization check audit details
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct AuthorizationCheckDetails {
    /// Subject being checked
    pub subject: String,
    /// Resource being accessed
    pub resource: String,
    /// Permission being checked
    pub permission: String,
    /// Authorization decision
    pub decision: Decision,
    /// Evaluation duration in milliseconds
    pub duration_ms: u64,
    /// Optional context data used in evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    /// Number of relationships evaluated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships_evaluated: Option<usize>,
    /// Whether trace was enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traced: Option<bool>,
}

/// Relationship write audit details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipWriteDetails {
    /// Number of relationships written
    pub count: usize,
    /// Sample relationships (limited to first 10 for brevity)
    pub sample: Vec<RelationshipRecord>,
    /// Storage revision after write
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// Relationship delete audit details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipDeleteDetails {
    /// Number of relationships deleted
    pub count: usize,
    /// Sample relationships (limited to first 10 for brevity)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample: Option<Vec<RelationshipRecord>>,
    /// Delete filter used (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<DeleteFilterRecord>,
    /// Storage revision after delete
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// Resource listing audit details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceListDetails {
    /// Subject listing resources for
    pub subject: String,
    /// Resource type filter
    pub resource_type: String,
    /// Permission checked
    pub permission: String,
    /// Number of resources returned
    pub result_count: usize,
    /// Whether results were paginated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paginated: Option<bool>,
}

/// Subject listing audit details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectListDetails {
    /// Resource being queried
    pub resource: String,
    /// Relation being checked
    pub relation: String,
    /// Number of subjects returned
    pub result_count: usize,
    /// Subject type filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
}

/// Expand operation audit details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpandDetails {
    /// Resource being expanded
    pub resource: String,
    /// Relation being expanded
    pub relation: String,
    /// Number of users in expanded set
    pub user_count: usize,
}

/// Simulation audit details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationDetails {
    /// Subject in simulation
    pub subject: String,
    /// Resource in simulation
    pub resource: String,
    /// Permission in simulation
    pub permission: String,
    /// Simulation decision
    pub decision: Decision,
    /// Number of context relationships used
    pub context_relationship_count: usize,
}

/// Relationship record for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipRecord {
    pub resource: String,
    pub relation: String,
    pub subject: String,
}

/// Delete filter record for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteFilterRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// Audit event details (tagged union)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventDetails {
    AuthorizationCheck(AuthorizationCheckDetails),
    RelationshipWrite(RelationshipWriteDetails),
    RelationshipDelete(RelationshipDeleteDetails),
    ResourceList(ResourceListDetails),
    SubjectList(SubjectListDetails),
    Expand(ExpandDetails),
    Simulation(SimulationDetails),
}

/// Complete audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event metadata
    #[serde(flatten)]
    pub metadata: AuditMetadata,
    /// Event-specific details
    #[serde(flatten)]
    pub details: AuditEventDetails,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(metadata: AuditMetadata, details: AuditEventDetails) -> Self {
        Self { metadata, details }
    }

    /// Generate a unique event ID
    pub fn generate_event_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros();

        format!("audit-{}-{}", timestamp, counter)
    }

    /// Get current timestamp in RFC3339 format
    pub fn current_timestamp() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

/// Audit logger configuration
#[derive(Debug, Clone, bon::Builder)]
pub struct AuditConfig {
    /// Enable audit logging
    #[builder(default = true)]
    pub enabled: bool,
    /// Log authorization checks
    #[builder(default = true)]
    pub log_authorization_checks: bool,
    /// Log relationship writes
    #[builder(default = true)]
    pub log_relationship_writes: bool,
    /// Log relationship deletes
    #[builder(default = true)]
    pub log_relationship_deletes: bool,
    /// Log resource listings
    #[builder(default = true)]
    pub log_resource_lists: bool,
    /// Log subject listings
    #[builder(default = true)]
    pub log_subject_lists: bool,
    /// Log expand operations
    #[builder(default = true)]
    pub log_expand: bool,
    /// Log simulations
    #[builder(default = true)]
    pub log_simulations: bool,
    /// Sample rate (0.0-1.0) for high-volume operations
    #[builder(default = 1.0)]
    pub sample_rate: f64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_authorization_checks: true,
            log_relationship_writes: true,
            log_relationship_deletes: true,
            log_resource_lists: true,
            log_subject_lists: true,
            log_expand: true,
            log_simulations: true,
            sample_rate: 1.0, // Log everything by default
        }
    }
}

/// Audit logger
pub struct AuditLogger {
    config: Arc<AuditConfig>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(config: AuditConfig) -> Self {
        Self { config: Arc::new(config) }
    }

    /// Create a disabled audit logger
    pub fn disabled() -> Self {
        Self { config: Arc::new(AuditConfig { enabled: false, ..Default::default() }) }
    }

    /// Log an audit event
    pub fn log(&self, event: AuditEvent) {
        if !self.config.enabled {
            return;
        }

        let event_type_str = format!("{:?}", event.metadata.event_type).to_lowercase();

        // Check sampling
        if self.config.sample_rate < 1.0 {
            use rand::Rng;
            let sample: f64 = rand::rng().random();
            if sample > self.config.sample_rate {
                crate::metrics::record_audit_event_sampled(&event_type_str);
                return;
            }
        }

        // Check if this event type should be logged
        let should_log = match &event.details {
            AuditEventDetails::AuthorizationCheck(_) => self.config.log_authorization_checks,
            AuditEventDetails::RelationshipWrite(_) => self.config.log_relationship_writes,
            AuditEventDetails::RelationshipDelete(_) => self.config.log_relationship_deletes,
            AuditEventDetails::ResourceList(_) => self.config.log_resource_lists,
            AuditEventDetails::SubjectList(_) => self.config.log_subject_lists,
            AuditEventDetails::Expand(_) => self.config.log_expand,
            AuditEventDetails::Simulation(_) => self.config.log_simulations,
        };

        if !should_log {
            return;
        }

        // Serialize to JSON and log
        match serde_json::to_string(&event) {
            Ok(json) => {
                info!(target: "inferadb_audit", "{}", json);
                crate::metrics::record_audit_event(&event_type_str);
            },
            Err(e) => {
                error!(target: "inferadb_audit", "Failed to serialize audit event: {}", e);
                crate::metrics::record_audit_error("serialization_error");
            },
        }
    }

    /// Check if audit logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new(AuditConfig::default())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ===== TDD tests for bon::Builder pattern =====

    #[test]
    fn test_audit_metadata_builder() {
        let metadata = AuditMetadata::builder()
            .event_id("audit-123")
            .timestamp("2025-01-01T00:00:00.000Z")
            .event_type(AuditEventType::AuthorizationCheck)
            .actor("user:alice")
            .build();

        assert_eq!(metadata.event_id, "audit-123");
        assert_eq!(metadata.actor, "user:alice");
        assert!(metadata.client_ip.is_none());
        assert!(metadata.user_agent.is_none());
        assert!(metadata.request_id.is_none());
        assert!(metadata.org_id.is_none());
    }

    #[test]
    fn test_audit_metadata_builder_with_optional_fields() {
        let metadata = AuditMetadata::builder()
            .event_id("audit-456")
            .timestamp("2025-01-01T00:00:00.000Z")
            .event_type(AuditEventType::RelationshipWrite)
            .actor("admin:bob")
            .client_ip("192.168.1.100")
            .user_agent("InferaDB-SDK/2.0")
            .request_id("req-789")
            .org_id("org-acme")
            .build();

        assert_eq!(metadata.client_ip, Some("192.168.1.100".to_string()));
        assert_eq!(metadata.user_agent, Some("InferaDB-SDK/2.0".to_string()));
        assert_eq!(metadata.request_id, Some("req-789".to_string()));
        assert_eq!(metadata.org_id, Some("org-acme".to_string()));
    }

    #[test]
    fn test_authorization_check_details_builder() {
        let details = AuthorizationCheckDetails::builder()
            .subject("user:alice")
            .resource("document:readme")
            .permission("read")
            .decision(Decision::Allow)
            .duration_ms(5)
            .build();

        assert_eq!(details.subject, "user:alice");
        assert_eq!(details.resource, "document:readme");
        assert_eq!(details.permission, "read");
        assert_eq!(details.decision, Decision::Allow);
        assert_eq!(details.duration_ms, 5);
        assert!(details.context.is_none());
        assert!(details.relationships_evaluated.is_none());
        assert!(details.traced.is_none());
    }

    #[test]
    fn test_audit_config_builder_defaults() {
        let config = AuditConfig::builder().build();

        // All fields should default to true (matching Default impl)
        assert!(config.enabled);
        assert!(config.log_authorization_checks);
        assert!(config.log_relationship_writes);
        assert!(config.log_relationship_deletes);
        assert!(config.log_resource_lists);
        assert!(config.log_subject_lists);
        assert!(config.log_expand);
        assert!(config.log_simulations);
        assert_eq!(config.sample_rate, 1.0);
    }

    #[test]
    fn test_audit_config_builder_custom() {
        let config = AuditConfig::builder()
            .enabled(true)
            .log_authorization_checks(true)
            .log_relationship_writes(false) // Override
            .sample_rate(0.5)
            .build();

        assert!(config.log_authorization_checks);
        assert!(!config.log_relationship_writes);
        assert_eq!(config.sample_rate, 0.5);
    }

    #[test]
    fn test_audit_config_builder_serde_equivalence() {
        let built = AuditConfig::builder().build();
        let default_impl = AuditConfig::default();

        // Builder with all defaults should match Default impl
        assert_eq!(built.enabled, default_impl.enabled);
        assert_eq!(built.log_authorization_checks, default_impl.log_authorization_checks);
        assert_eq!(built.sample_rate, default_impl.sample_rate);
    }

    #[test]
    fn test_audit_event_id_generation() {
        let id1 = AuditEvent::generate_event_id();
        let id2 = AuditEvent::generate_event_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("audit-"));
    }

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert!(config.log_authorization_checks);
        assert_eq!(config.sample_rate, 1.0);
    }

    #[test]
    fn test_audit_logger_disabled() {
        let logger = AuditLogger::disabled();
        assert!(!logger.is_enabled());
    }

    #[test]
    fn test_authorization_check_event() {
        let metadata = AuditMetadata {
            event_id: AuditEvent::generate_event_id(),
            timestamp: AuditEvent::current_timestamp(),
            event_type: AuditEventType::AuthorizationCheck,
            actor: "user:alice".to_string(),
            client_ip: Some("192.168.1.100".to_string()),
            user_agent: Some("InferaDB-Client/1.0".to_string()),
            request_id: Some("req-123".to_string()),
            org_id: Some("tenant-1".to_string()),
        };

        let details = AuditEventDetails::AuthorizationCheck(AuthorizationCheckDetails {
            subject: "user:alice".to_string(),
            resource: "document:readme".to_string(),
            permission: "viewer".to_string(),
            decision: Decision::Allow,
            duration_ms: 5,
            context: None,
            relationships_evaluated: Some(3),
            traced: Some(false),
        });

        let event = AuditEvent::new(metadata, details);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("user:alice"));
        assert!(json.contains("authorization_check"));
        assert!(json.contains("allow"));
    }

    #[test]
    fn test_relationship_write_event() {
        let metadata = AuditMetadata {
            event_id: AuditEvent::generate_event_id(),
            timestamp: AuditEvent::current_timestamp(),
            event_type: AuditEventType::RelationshipWrite,
            actor: "admin:bob".to_string(),
            client_ip: None,
            user_agent: None,
            request_id: None,
            org_id: None,
        };

        let details = AuditEventDetails::RelationshipWrite(RelationshipWriteDetails {
            count: 2,
            sample: vec![
                RelationshipRecord {
                    resource: "document:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                },
                RelationshipRecord {
                    resource: "document:readme".to_string(),
                    relation: "editor".to_string(),
                    subject: "user:bob".to_string(),
                },
            ],
            revision: Some("rev-456".to_string()),
        });

        let event = AuditEvent::new(metadata, details);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("relationship_write"));
        assert!(json.contains("admin:bob"));
        assert_eq!(event.metadata.event_type, AuditEventType::RelationshipWrite);
    }

    #[test]
    fn test_decision_serialization() {
        let allow = Decision::Allow;
        let deny = Decision::Deny;

        let allow_json = serde_json::to_string(&allow).unwrap();
        let deny_json = serde_json::to_string(&deny).unwrap();

        assert_eq!(allow_json, "\"allow\"");
        assert_eq!(deny_json, "\"deny\"");
    }

    #[test]
    fn test_audit_logger_sampling() {
        let config = AuditConfig {
            enabled: true,
            sample_rate: 0.0, // Never log
            ..Default::default()
        };

        let logger = AuditLogger::new(config);

        let metadata = AuditMetadata {
            event_id: AuditEvent::generate_event_id(),
            timestamp: AuditEvent::current_timestamp(),
            event_type: AuditEventType::AuthorizationCheck,
            actor: "user:test".to_string(),
            client_ip: None,
            user_agent: None,
            request_id: None,
            org_id: None,
        };

        let details = AuditEventDetails::AuthorizationCheck(AuthorizationCheckDetails {
            subject: "user:test".to_string(),
            resource: "test:resource".to_string(),
            permission: "view".to_string(),
            decision: Decision::Allow,
            duration_ms: 1,
            context: None,
            relationships_evaluated: None,
            traced: None,
        });

        let event = AuditEvent::new(metadata, details);

        // Should not panic even with 0 sample rate
        logger.log(event);
    }
}
