// SPDX-License-Identifier: TBD
//
// Audit Event Definitions
//
// Each variant represents a security-relevant action that must be recorded
// for compliance and forensic purposes.
//
// NIST SP 800-53 Rev. 5:
// - AU-2 (Audit Events): This enum defines the complete set of auditable events.
//   Every security-relevant action in the system maps to exactly one variant.
// - AU-3 (Content of Audit Records): Each variant carries the contextual fields
//   required for meaningful audit analysis: who (DN, source IP), what (event type),
//   when (timestamp), where (site), and outcome (success/failure/reason).
// - AU-8 (Time Stamps): All events include a UTC timestamp from the system clock.
//   Operators are responsible for NTP synchronization (NIST AU-8(1)).

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::SocketAddr;

/// A structured audit event carrying all context required by NIST AU-3.
///
/// Events are serialized to JSON for both tracing output and database
/// persistence in the runtime.audit_queue table.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type", content = "details", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum AuditEvent {
    /// A bind (authentication) attempt was made.
    /// Logged regardless of outcome for AC-7 tracking.
    BindAttempt {
        timestamp: DateTime<Utc>,
        source_addr: String,
        dn: String,
        outcome: BindOutcome,
    },

    /// A search operation was requested.
    SearchRequest {
        timestamp: DateTime<Utc>,
        source_addr: String,
        bound_dn: String,
        base_dn: String,
        scope: String,
        filter_summary: String,
    },

    /// A search operation completed.
    SearchComplete {
        timestamp: DateTime<Utc>,
        source_addr: String,
        bound_dn: String,
        base_dn: String,
        entries_returned: usize,
        result_code: i64,
    },

    /// A Password Modify extended operation was processed.
    PasswordModify {
        timestamp: DateTime<Utc>,
        source_addr: String,
        broker_dn: String,
        target_dn: String,
        success: bool,
        failure_reason: Option<String>,
    },

    /// A rate limit was triggered for a DN.
    /// NIST AC-7: Unsuccessful logon attempt threshold exceeded.
    RateLimitTriggered {
        timestamp: DateTime<Utc>,
        source_addr: String,
        dn: String,
        attempt_count: u32,
        window_secs: u64,
    },

    /// A TLS handshake or connection error occurred.
    TlsError {
        timestamp: DateTime<Utc>,
        source_addr: String,
        error_detail: String,
    },

    /// Configuration was loaded at startup.
    /// NIST CM-6: Configuration management event.
    ConfigLoaded {
        timestamp: DateTime<Utc>,
        config_path: String,
        bind_addr: String,
        port: u16,
        replication_enabled: bool,
    },

    /// The LDAPS service started successfully.
    ServiceStarted {
        timestamp: DateTime<Utc>,
        bind_addr: String,
        port: u16,
        tls_min_version: String,
    },

    /// The LDAPS service is shutting down.
    ServiceStopped {
        timestamp: DateTime<Utc>,
        reason: String,
    },

    /// A connection was established.
    ConnectionOpened {
        timestamp: DateTime<Utc>,
        source_addr: String,
    },

    /// A connection was closed.
    ConnectionClosed {
        timestamp: DateTime<Utc>,
        source_addr: String,
        messages_processed: u64,
        duration_secs: f64,
    },
}

/// Outcome of a bind attempt.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
#[allow(dead_code)]
pub enum BindOutcome {
    Success,
    InvalidCredentials,
    AccountLocked,
    UserNotFound,
    AccountDisabled,
    RateLimited,
    InternalError { detail: String },
}

impl AuditEvent {
    /// Create a BindAttempt event with the current timestamp.
    pub fn bind_attempt(source: SocketAddr, dn: &str, outcome: BindOutcome) -> Self {
        Self::BindAttempt {
            timestamp: Utc::now(),
            source_addr: source.to_string(),
            dn: dn.to_string(),
            outcome,
        }
    }

    /// Create a SearchRequest event with the current timestamp.
    #[allow(dead_code)]
    pub fn search_request(
        source: SocketAddr,
        bound_dn: &str,
        base_dn: &str,
        scope: &str,
        filter_summary: &str,
    ) -> Self {
        Self::SearchRequest {
            timestamp: Utc::now(),
            source_addr: source.to_string(),
            bound_dn: bound_dn.to_string(),
            base_dn: base_dn.to_string(),
            scope: scope.to_string(),
            filter_summary: filter_summary.to_string(),
        }
    }

    /// Create a PasswordModify event with the current timestamp.
    pub fn password_modify(
        source: SocketAddr,
        broker_dn: &str,
        target_dn: &str,
        success: bool,
        failure_reason: Option<&str>,
    ) -> Self {
        Self::PasswordModify {
            timestamp: Utc::now(),
            source_addr: source.to_string(),
            broker_dn: broker_dn.to_string(),
            target_dn: target_dn.to_string(),
            success,
            failure_reason: failure_reason.map(|s| s.to_string()),
        }
    }

    /// Create a RateLimitTriggered event with the current timestamp.
    #[allow(dead_code)]
    pub fn rate_limit_triggered(
        source: SocketAddr,
        dn: &str,
        attempt_count: u32,
        window_secs: u64,
    ) -> Self {
        Self::RateLimitTriggered {
            timestamp: Utc::now(),
            source_addr: source.to_string(),
            dn: dn.to_string(),
            attempt_count,
            window_secs,
        }
    }

    /// Create a ServiceStarted event with the current timestamp.
    pub fn service_started(bind_addr: &str, port: u16, tls_min_version: &str) -> Self {
        Self::ServiceStarted {
            timestamp: Utc::now(),
            bind_addr: bind_addr.to_string(),
            port,
            tls_min_version: tls_min_version.to_string(),
        }
    }

    /// Create a ServiceStopped event with the current timestamp.
    pub fn service_stopped(reason: &str) -> Self {
        Self::ServiceStopped {
            timestamp: Utc::now(),
            reason: reason.to_string(),
        }
    }

    /// Create a ConfigLoaded event with the current timestamp.
    pub fn config_loaded(
        config_path: &str,
        bind_addr: &str,
        port: u16,
        replication_enabled: bool,
    ) -> Self {
        Self::ConfigLoaded {
            timestamp: Utc::now(),
            config_path: config_path.to_string(),
            bind_addr: bind_addr.to_string(),
            port,
            replication_enabled,
        }
    }

    /// Return the event type string for database storage.
    #[must_use]
    pub fn event_type_name(&self) -> &'static str {
        match self {
            Self::BindAttempt { .. } => "bind_attempt",
            Self::SearchRequest { .. } => "search_request",
            Self::SearchComplete { .. } => "search_complete",
            Self::PasswordModify { .. } => "password_modify",
            Self::RateLimitTriggered { .. } => "rate_limit_triggered",
            Self::TlsError { .. } => "tls_error",
            Self::ConfigLoaded { .. } => "config_loaded",
            Self::ServiceStarted { .. } => "service_started",
            Self::ServiceStopped { .. } => "service_stopped",
            Self::ConnectionOpened { .. } => "connection_opened",
            Self::ConnectionClosed { .. } => "connection_closed",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321)
    }

    #[test]
    fn test_bind_attempt_serialization() {
        let event = AuditEvent::bind_attempt(
            test_addr(),
            "cn=admin,dc=example,dc=com",
            BindOutcome::Success,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("bind_attempt"));
        assert!(json.contains("cn=admin"));
    }

    #[test]
    fn test_event_type_names() {
        let event = AuditEvent::service_started("0.0.0.0", 636, "1.2");
        assert_eq!(event.event_type_name(), "service_started");

        let event = AuditEvent::service_stopped("SIGTERM");
        assert_eq!(event.event_type_name(), "service_stopped");
    }

    #[test]
    fn test_password_modify_event() {
        let event = AuditEvent::password_modify(
            test_addr(),
            "cn=broker,ou=services,dc=example,dc=com",
            "cn=jdoe,dc=example,dc=com",
            true,
            None,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("password_modify"));
        assert!(json.contains("cn=broker"));
        assert!(json.contains("cn=jdoe"));
        assert_eq!(event.event_type_name(), "password_modify");

        // Test failure case with reason.
        let event = AuditEvent::password_modify(
            test_addr(),
            "cn=broker,ou=services,dc=example,dc=com",
            "cn=missing,dc=example,dc=com",
            false,
            Some("target user not found"),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("target user not found"));
    }

    #[test]
    fn test_rate_limit_event() {
        let event = AuditEvent::rate_limit_triggered(test_addr(), "cn=user", 6, 300);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("rate_limit_triggered"));
        assert!(json.contains("\"attempt_count\":6"));
    }
}
