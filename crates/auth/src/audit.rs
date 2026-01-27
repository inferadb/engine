//! Audit Logging
//!
//! This module provides structured audit logging for authentication and authorization events.
//! Audit logs are used for security monitoring, compliance, and incident response.
//!
//! ## Event Types
//!
//! - **AuthenticationSuccess**: Successful authentication
//! - **AuthenticationFailure**: Failed authentication attempt
//! - **ScopeViolation**: Attempt to access resource without required scope
//! - **TenantIsolationViolation**: Attempt to access another tenant's resources
//!
//! ## Usage
//!
//! ```ignore
//! use inferadb_engine_auth::audit::{AuditEvent, log_audit_event};
//!
//! // Log successful authentication
//! log_audit_event(AuditEvent::AuthenticationSuccess {
//!     tenant_id: "acme".to_string(),
//!     method: "tenant_jwt".to_string(),
//!     timestamp: chrono::Utc::now(),
//!     ip_address: Some("192.168.1.1".to_string()),
//! });
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Audit event types for authentication and authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum AuditEvent {
    /// Successful authentication event
    AuthenticationSuccess {
        /// Tenant ID that authenticated
        tenant_id: String,
        /// Authentication method used (tenant_jwt, oauth_jwt, internal_jwt)
        method: String,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// IP address of the client (if available)
        #[serde(skip_serializing_if = "Option::is_none")]
        ip_address: Option<String>,
    },

    /// Failed authentication attempt
    AuthenticationFailure {
        /// Tenant ID (if extractable from token, otherwise "unknown")
        tenant_id: String,
        /// Authentication method attempted
        method: String,
        /// Error that occurred
        error: String,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// IP address of the client (if available)
        #[serde(skip_serializing_if = "Option::is_none")]
        ip_address: Option<String>,
    },

    /// Scope violation - authenticated but missing required scope
    ScopeViolation {
        /// Tenant ID
        tenant_id: String,
        /// Required scope that was missing
        required_scope: String,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
    },

    /// Tenant isolation violation - attempt to access another tenant's resources
    TenantIsolationViolation {
        /// Authenticated tenant ID
        tenant_id: String,
        /// Tenant ID that was attempted to be accessed
        attempted_tenant: String,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
    },
}

/// Log an audit event
///
/// This function serializes the event to JSON and logs it using the tracing infrastructure.
/// - Success events are logged at INFO level
/// - Failure and violation events are logged at WARN level
///
/// # Arguments
///
/// * `event` - The audit event to log
pub fn log_audit_event(event: AuditEvent) {
    // Serialize event to JSON
    let json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize audit event");
            return;
        },
    };

    // Log at appropriate level based on event type
    match &event {
        AuditEvent::AuthenticationSuccess { tenant_id, method, timestamp, ip_address } => {
            tracing::info!(
                audit_event = %json,
                tenant_id = %tenant_id,
                method = %method,
                timestamp = %timestamp,
                ip_address = ?ip_address,
                "Authentication succeeded"
            );
        },
        AuditEvent::AuthenticationFailure { tenant_id, method, error, timestamp, ip_address } => {
            tracing::warn!(
                audit_event = %json,
                tenant_id = %tenant_id,
                method = %method,
                error = %error,
                timestamp = %timestamp,
                ip_address = ?ip_address,
                "Authentication failed"
            );
        },
        AuditEvent::ScopeViolation { tenant_id, required_scope, timestamp } => {
            tracing::warn!(
                audit_event = %json,
                tenant_id = %tenant_id,
                required_scope = %required_scope,
                timestamp = %timestamp,
                "Scope violation"
            );
        },
        AuditEvent::TenantIsolationViolation { tenant_id, attempted_tenant, timestamp } => {
            tracing::warn!(
                audit_event = %json,
                tenant_id = %tenant_id,
                attempted_tenant = %attempted_tenant,
                timestamp = %timestamp,
                "Tenant isolation violation"
            );
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_serialization_authentication_success() {
        let event = AuditEvent::AuthenticationSuccess {
            tenant_id: "acme".to_string(),
            method: "tenant_jwt".to_string(),
            timestamp: DateTime::from_timestamp(1234567890, 0).unwrap(),
            ip_address: Some("192.168.1.1".to_string()),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("AuthenticationSuccess"));
        assert!(json.contains("acme"));
        assert!(json.contains("tenant_jwt"));
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn test_audit_event_serialization_authentication_failure() {
        let event = AuditEvent::AuthenticationFailure {
            tenant_id: "acme".to_string(),
            method: "tenant_jwt".to_string(),
            error: "Token expired".to_string(),
            timestamp: DateTime::from_timestamp(1234567890, 0).unwrap(),
            ip_address: Some("192.168.1.1".to_string()),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("AuthenticationFailure"));
        assert!(json.contains("acme"));
        assert!(json.contains("Token expired"));
    }

    #[test]
    fn test_audit_event_serialization_scope_violation() {
        let event = AuditEvent::ScopeViolation {
            tenant_id: "acme".to_string(),
            required_scope: "admin".to_string(),
            timestamp: DateTime::from_timestamp(1234567890, 0).unwrap(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ScopeViolation"));
        assert!(json.contains("acme"));
        assert!(json.contains("admin"));
    }

    #[test]
    fn test_audit_event_serialization_tenant_isolation_violation() {
        let event = AuditEvent::TenantIsolationViolation {
            tenant_id: "acme".to_string(),
            attempted_tenant: "bigcorp".to_string(),
            timestamp: DateTime::from_timestamp(1234567890, 0).unwrap(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("TenantIsolationViolation"));
        assert!(json.contains("acme"));
        assert!(json.contains("bigcorp"));
    }

    #[test]
    fn test_audit_event_without_ip_address() {
        let event = AuditEvent::AuthenticationSuccess {
            tenant_id: "acme".to_string(),
            method: "internal_jwt".to_string(),
            timestamp: DateTime::from_timestamp(1234567890, 0).unwrap(),
            ip_address: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        // ip_address should not be present when None
        assert!(!json.contains("ip_address"));
    }

    #[test]
    fn test_log_audit_event_success() {
        // This test verifies that log_audit_event doesn't panic
        let event = AuditEvent::AuthenticationSuccess {
            tenant_id: "test".to_string(),
            method: "test_method".to_string(),
            timestamp: Utc::now(),
            ip_address: Some("127.0.0.1".to_string()),
        };

        // Should not panic
        log_audit_event(event);
    }

    #[test]
    fn test_log_audit_event_failure() {
        let event = AuditEvent::AuthenticationFailure {
            tenant_id: "test".to_string(),
            method: "test_method".to_string(),
            error: "test error".to_string(),
            timestamp: Utc::now(),
            ip_address: None,
        };

        // Should not panic
        log_audit_event(event);
    }

    #[test]
    fn test_log_audit_event_scope_violation() {
        let event = AuditEvent::ScopeViolation {
            tenant_id: "test".to_string(),
            required_scope: "admin".to_string(),
            timestamp: Utc::now(),
        };

        // Should not panic
        log_audit_event(event);
    }

    #[test]
    fn test_log_audit_event_tenant_isolation_violation() {
        let event = AuditEvent::TenantIsolationViolation {
            tenant_id: "test".to_string(),
            attempted_tenant: "other".to_string(),
            timestamp: Utc::now(),
        };

        // Should not panic
        log_audit_event(event);
    }
}
