// SPDX-License-Identifier: TBD
//
// Audit Logging Subsystem
//
// Provides the AuditLogger that emits structured security events via tracing
// AND persists them to the runtime.audit_queue table for durable forwarding
// to the central SIEM.
//
// NIST SP 800-53 Rev. 5:
// - AU-2 (Audit Events): All security-relevant events are captured.
// - AU-3 (Content of Audit Records): Events carry timestamps, source IPs,
//   DNs, outcomes, and other contextual fields.
// - AU-5 (Response to Audit Processing Failures): If database persistence
//   fails, the event is still emitted via tracing (dual-write strategy).
//   The server does not stop processing LDAP requests on audit failure,
//   but the failure is itself logged as a warning.
// - AU-6 (Audit Review): Events in the audit_queue are available for
//   asynchronous forwarding to a central SIEM for review.
// - AU-8 (Time Stamps): All events use UTC timestamps.

pub mod events;

use events::AuditEvent;
use sqlx::PgPool;
use std::sync::Arc;

/// The audit logger: dual-writes events to tracing and the database audit queue.
///
/// This struct is cheaply cloneable (wraps an Arc<PgPool>) and is shared
/// across all connection handlers.
#[derive(Clone)]
pub struct AuditLogger {
    pool: Option<Arc<PgPool>>,
    enabled: bool,
}

impl AuditLogger {
    /// Create a new AuditLogger backed by the given database pool.
    ///
    /// If `enabled` is false, events are still emitted via tracing but
    /// not persisted to the database.
    pub fn new(pool: Arc<PgPool>, enabled: bool) -> Self {
        Self {
            pool: Some(pool),
            enabled,
        }
    }

    /// Create an AuditLogger that only emits to tracing (no database).
    ///
    /// Useful for startup events before the database is connected, or
    /// for testing.
    pub fn tracing_only() -> Self {
        Self {
            pool: None,
            enabled: true,
        }
    }

    /// Emit an audit event.
    ///
    /// The event is always emitted via tracing for immediate observability.
    /// If database persistence is configured, the event is also enqueued
    /// in the runtime.audit_queue table.
    ///
    /// NIST AU-5: If database write fails, the event is still logged via
    /// tracing, and a warning is emitted about the persistence failure.
    pub async fn log(&self, event: AuditEvent) {
        // Always emit via tracing for immediate observability.
        self.emit_tracing(&event);

        // Persist to database if enabled and pool is available.
        if self.enabled {
            if let Some(pool) = &self.pool {
                self.persist_event(pool, &event).await;
            }
        }
    }

    /// Emit an audit event synchronously via tracing only (no DB write).
    ///
    /// Use this for events that occur in synchronous contexts (e.g., during
    /// configuration loading before the async runtime is fully initialized).
    pub fn log_sync(&self, event: &AuditEvent) {
        self.emit_tracing(event);
    }

    /// Emit the event to the tracing subscriber as a structured JSON event.
    fn emit_tracing(&self, event: &AuditEvent) {
        // Serialize the event to JSON for structured logging.
        match serde_json::to_string(event) {
            Ok(json) => {
                tracing::info!(
                    audit_event = %json,
                    event_type = event.event_type_name(),
                    "audit"
                );
            }
            Err(e) => {
                // Serialization failure should not happen, but handle defensively.
                tracing::error!(
                    error = %e,
                    event_type = event.event_type_name(),
                    "failed to serialize audit event"
                );
            }
        }
    }

    /// Persist the event to the runtime.audit_queue table.
    ///
    /// NIST AU-5: On failure, log a warning but do not halt processing.
    async fn persist_event(&self, pool: &PgPool, event: &AuditEvent) {
        let event_type = event.event_type_name();
        let event_data = match serde_json::to_value(event) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    event_type = event_type,
                    "failed to serialize audit event for persistence"
                );
                return;
            }
        };

        let result = sqlx::query(
            r#"
            INSERT INTO runtime.audit_queue (event_type, event_data)
            VALUES ($1, $2)
            "#,
        )
        .bind(event_type)
        .bind(&event_data)
        .execute(pool)
        .await;

        if let Err(e) = result {
            // NIST AU-5: Audit processing failure — log but do not halt.
            tracing::warn!(
                error = %e,
                event_type = event_type,
                "failed to persist audit event to database (event was still logged via tracing)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use events::BindOutcome;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    #[tokio::test]
    async fn test_tracing_only_logger_does_not_panic() {
        let logger = AuditLogger::tracing_only();
        let event = AuditEvent::bind_attempt(test_addr(), "cn=test", BindOutcome::Success);
        // Should not panic even without a database.
        logger.log(event).await;
    }

    #[test]
    fn test_sync_logging_does_not_panic() {
        let logger = AuditLogger::tracing_only();
        let event = AuditEvent::service_started("0.0.0.0", 636, "1.2");
        logger.log_sync(&event);
    }
}
