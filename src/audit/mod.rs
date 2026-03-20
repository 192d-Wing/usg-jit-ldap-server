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
//   fails, behavior is governed by the configured AuditFailurePolicy.
//   In fail_open mode (default), the event is still emitted via tracing and
//   the server continues. In fail_closed mode, the calling operation is
//   rejected with an error.
// - AU-6 (Audit Review): Events in the audit_queue are available for
//   asynchronous forwarding to a central SIEM for review.
// - AU-8 (Time Stamps): All events use UTC timestamps.

pub mod events;

use events::AuditEvent;
use crate::config::AuditFailurePolicy;
use sqlx::PgPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by fail-closed audit operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit event persistence failed: {0}")]
    PersistenceFailed(String),
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// The audit logger: dual-writes events to tracing and the database audit queue.
///
/// This struct is cheaply cloneable (wraps an Arc<PgPool>) and is shared
/// across all connection handlers.
#[derive(Clone)]
pub struct AuditLogger {
    pool: Option<Arc<PgPool>>,
    enabled: bool,
    failure_policy: AuditFailurePolicy,
    failure_count: Arc<AtomicU64>,
}

impl AuditLogger {
    /// Create a new AuditLogger backed by the given database pool.
    ///
    /// If `enabled` is false, events are still emitted via tracing but
    /// not persisted to the database.
    pub fn new(pool: Arc<PgPool>, enabled: bool, failure_policy: AuditFailurePolicy) -> Self {
        Self {
            pool: Some(pool),
            enabled,
            failure_policy,
            failure_count: Arc::new(AtomicU64::new(0)),
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
            failure_policy: AuditFailurePolicy::default(),
            failure_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Emit an audit event, returning an error if persistence fails and
    /// the failure policy is fail-closed.
    ///
    /// NIST AU-5: In fail_closed mode, callers MUST handle the error by
    /// rejecting the in-flight operation. In fail_open mode, persistence
    /// failures are logged as warnings but Ok(()) is always returned.
    pub async fn log_checked(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.emit_tracing(&event);
        if self.enabled {
            if let Some(pool) = &self.pool {
                if let Err(msg) = self.persist_event_checked(pool, &event).await {
                    self.failure_count.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        error = %msg,
                        failures = self.failure_count.load(Ordering::Relaxed),
                        "audit persistence failure"
                    );
                    if self.failure_policy == AuditFailurePolicy::FailClosed {
                        return Err(AuditError::PersistenceFailed(msg));
                    }
                }
            }
        }
        Ok(())
    }

    /// Fire-and-forget audit event emission.
    ///
    /// The event is always emitted via tracing for immediate observability.
    /// If database persistence is configured, the event is also enqueued
    /// in the runtime.audit_queue table. Persistence failures are logged
    /// as warnings but never propagated to the caller.
    pub async fn log(&self, event: AuditEvent) {
        let _ = self.log_checked(event).await;
    }

    /// Emit an audit event synchronously via tracing only (no DB write).
    ///
    /// Use this for events that occur in synchronous contexts (e.g., during
    /// configuration loading before the async runtime is fully initialized).
    pub fn log_sync(&self, event: &AuditEvent) {
        self.emit_tracing(event);
    }

    /// Return the cumulative number of audit persistence failures.
    ///
    /// Useful for health checks and monitoring/alerting dashboards.
    #[must_use]
    pub fn failure_count(&self) -> u64 {
        self.failure_count.load(Ordering::Relaxed)
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

    /// Persist the event to the runtime.audit_queue table, returning an error
    /// string on failure instead of silently swallowing it.
    async fn persist_event_checked(&self, pool: &PgPool, event: &AuditEvent) -> Result<(), String> {
        let event_type = event.event_type_name();
        let event_data = serde_json::to_value(event).map_err(|e| {
            format!("failed to serialize audit event for persistence: {e}")
        })?;

        sqlx::query(
            r#"
            INSERT INTO runtime.audit_queue (event_type, event_data)
            VALUES ($1, $2)
            "#,
        )
        .bind(event_type)
        .bind(&event_data)
        .execute(pool)
        .await
        .map_err(|e| format!("database write failed: {e}"))?;

        Ok(())
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

    #[tokio::test]
    async fn test_tracing_only_log_checked_succeeds() {
        let logger = AuditLogger::tracing_only();
        let event = AuditEvent::bind_attempt(test_addr(), "cn=test", BindOutcome::Success);
        // log_checked should succeed when there is no pool (nothing to fail).
        assert!(logger.log_checked(event).await.is_ok());
    }

    #[test]
    fn test_sync_logging_does_not_panic() {
        let logger = AuditLogger::tracing_only();
        let event = AuditEvent::service_started("0.0.0.0", 636, "1.2");
        logger.log_sync(&event);
    }

    #[test]
    fn test_failure_count_starts_at_zero() {
        let logger = AuditLogger::tracing_only();
        assert_eq!(logger.failure_count(), 0);
    }

    #[test]
    fn test_default_failure_policy_is_fail_open() {
        let logger = AuditLogger::tracing_only();
        assert_eq!(logger.failure_policy, AuditFailurePolicy::FailOpen);
    }
}
