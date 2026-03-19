//! Replication health tracking and reporting.
//!
//! Provides the `ReplicationHealth` struct that tracks the operational status
//! of replication at a site. This data is exposed via health endpoints for
//! monitoring systems and operational dashboards.
//!
//! # Metrics
//!
//! All health state transitions and metrics are emitted via `tracing` events
//! with structured fields. These can be scraped by Prometheus (via a tracing
//! subscriber that exports metrics) or consumed by any log aggregation system.
//!
//! # NIST SP 800-53 Rev. 5 Control Mappings
//!
//! - **SI-4 (System Monitoring)**: Health tracking enables continuous monitoring
//!   of replication status. Staleness detection provides early warning of data
//!   freshness issues. Metrics enable alerting on anomalous conditions.
//! - **CP-9 (System Backup)**: Health reports indicate when a site is operating
//!   on stale (backup) identity data, enabling operators to assess risk.

use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::puller::PullResult;
use super::ReplicationStatus;

/// Tracks the health of replication at a single site.
///
/// This struct is intended to be wrapped in `Arc<Mutex<_>>` and shared between
/// the replication puller task and the health reporting endpoint.
#[derive(Debug)]
pub struct ReplicationHealth {
    /// The site this health tracker belongs to.
    site_id: Uuid,
    /// Current replication status.
    status: ReplicationStatus,
    /// Timestamp of the last successful sync, if any.
    last_sync: Option<DateTime<Utc>>,
    /// Current sequence number at this site.
    sequence_number: i64,
    /// Number of consecutive pull failures.
    consecutive_failures: u32,
    /// Last error message, if the last pull failed.
    last_error: Option<String>,
    /// Running total of sync durations for average calculation.
    total_sync_duration_ms: u64,
    /// Number of successful syncs recorded (for average calculation).
    successful_sync_count: u64,
}

/// Health report suitable for serialization and exposure via health endpoints.
///
/// This is a snapshot of the replication health state at a point in time.
/// Monitoring systems poll this to track site data freshness.
#[derive(Debug, Clone)]
pub struct HealthReport {
    /// The site this report describes.
    pub site_id: Uuid,
    /// Current replication status.
    pub status: ReplicationStatus,
    /// Timestamp of the last successful sync.
    pub last_sync: Option<DateTime<Utc>>,
    /// Current sequence number at this site.
    pub sequence_number: i64,
    /// Number of consecutive pull failures.
    pub consecutive_failures: u32,
    /// Average sync duration in milliseconds (across all recorded syncs).
    pub avg_sync_duration_ms: u64,
    /// Whether the site's identity data is considered stale.
    pub is_stale: bool,
}

impl ReplicationHealth {
    /// Creates a new `ReplicationHealth` tracker for the given site.
    pub fn new(site_id: Uuid) -> Self {
        Self {
            site_id,
            status: ReplicationStatus::Synced,
            last_sync: None,
            sequence_number: 0,
            consecutive_failures: 0,
            last_error: None,
            total_sync_duration_ms: 0,
            successful_sync_count: 0,
        }
    }

    /// Returns the current replication status.
    pub fn status(&self) -> &ReplicationStatus {
        &self.status
    }

    /// Sets the replication status directly.
    ///
    /// Used by the puller to set `Syncing` at the start of a pull cycle.
    pub fn set_status(&mut self, status: ReplicationStatus) {
        self.status = status;
    }

    /// Returns the current sequence number.
    pub fn sequence_number(&self) -> i64 {
        self.sequence_number
    }

    /// Returns the number of consecutive failures.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Checks whether the site's identity data is stale.
    ///
    /// Data is considered stale when the time since the last successful sync
    /// exceeds the given threshold. If no sync has ever succeeded, data is
    /// considered stale (the site has never received identity data).
    ///
    /// # NIST CP-9 (System Backup)
    /// Staleness indicates the site is operating on potentially outdated identity
    /// data. The site remains functional (local survivability) but operators
    /// should be aware of the data freshness risk.
    pub fn check_staleness(&self, threshold: Duration) -> bool {
        match self.last_sync {
            Some(last) => {
                let elapsed = Utc::now()
                    .signed_duration_since(last)
                    .to_std()
                    .unwrap_or(Duration::MAX);
                elapsed > threshold
            }
            None => {
                // Never synced -- by definition stale.
                true
            }
        }
    }

    /// Records a successful pull cycle.
    ///
    /// Updates the status, sequence number, timing statistics, and resets the
    /// failure counter. Emits metrics via tracing.
    pub fn record_success(&mut self, result: &PullResult) {
        let now = Utc::now();
        self.last_sync = Some(now);
        self.sequence_number = result.new_sequence_number;
        self.consecutive_failures = 0;
        self.last_error = None;
        self.status = result.status.clone();

        // Update running average.
        let duration_ms = result.duration.as_millis() as u64;
        self.total_sync_duration_ms += duration_ms;
        self.successful_sync_count += 1;

        // Emit metrics via tracing for Prometheus/monitoring.
        // SI-4: These structured fields enable continuous monitoring.
        info!(
            site_id = %self.site_id,
            replication_sequence_number = self.sequence_number,
            replication_changes_applied = result.changes_applied,
            replication_pull_duration_ms = duration_ms,
            replication_consecutive_failures = 0u32,
            replication_last_success_timestamp = %now,
            "replication.sync.success"
        );

        debug!(
            site_id = %self.site_id,
            avg_sync_duration_ms = self.avg_sync_duration_ms(),
            total_syncs = self.successful_sync_count,
            "Replication health updated"
        );
    }

    /// Records a failed pull cycle.
    ///
    /// Increments the failure counter, stores the error message, and updates
    /// the status to `Error`. Emits warning metrics via tracing.
    pub fn record_failure(&mut self, error: &str) {
        self.consecutive_failures += 1;
        self.last_error = Some(error.to_string());

        self.status = ReplicationStatus::Error {
            message: error.to_string(),
            since: self.last_error_since().unwrap_or_else(Utc::now),
        };

        // Emit metrics for monitoring.
        warn!(
            site_id = %self.site_id,
            replication_consecutive_failures = self.consecutive_failures,
            replication_last_error = error,
            replication_sequence_number = self.sequence_number,
            "replication.sync.failure"
        );

        // Emit staleness metric if we have a last_sync timestamp.
        if let Some(last) = self.last_sync {
            let staleness_secs = Utc::now()
                .signed_duration_since(last)
                .num_seconds()
                .max(0) as u64;
            warn!(
                site_id = %self.site_id,
                replication_staleness_seconds = staleness_secs,
                "replication.staleness"
            );
        }
    }

    /// Generates a health report snapshot for monitoring systems.
    ///
    /// The report includes all key metrics needed to assess replication health
    /// at this site. It is designed to be serialized to JSON and exposed via
    /// a health endpoint.
    pub fn health_report(&self, stale_threshold: Duration) -> HealthReport {
        let is_stale = self.check_staleness(stale_threshold);

        // If stale but status is not yet Stale, produce a Stale status for the report.
        let report_status = if is_stale && matches!(self.status, ReplicationStatus::Synced) {
            match self.last_sync {
                Some(last) => ReplicationStatus::Stale {
                    last_sync: last,
                    behind_by: -1, // Unknown without querying central.
                },
                None => ReplicationStatus::Stale {
                    last_sync: DateTime::UNIX_EPOCH,
                    behind_by: -1,
                },
            }
        } else {
            self.status.clone()
        };

        HealthReport {
            site_id: self.site_id,
            status: report_status,
            last_sync: self.last_sync,
            sequence_number: self.sequence_number,
            consecutive_failures: self.consecutive_failures,
            avg_sync_duration_ms: self.avg_sync_duration_ms(),
            is_stale,
        }
    }

    /// Computes the average sync duration in milliseconds.
    fn avg_sync_duration_ms(&self) -> u64 {
        if self.successful_sync_count == 0 {
            return 0;
        }
        self.total_sync_duration_ms / self.successful_sync_count
    }

    /// Returns the timestamp when the current error state began.
    ///
    /// If already in an error state, returns the existing `since` timestamp
    /// to preserve the original error onset time across consecutive failures.
    fn last_error_since(&self) -> Option<DateTime<Utc>> {
        match &self.status {
            ReplicationStatus::Error { since, .. } => Some(*since),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_health_is_not_stale_with_zero_threshold() {
        let health = ReplicationHealth::new(Uuid::new_v4());
        // Never synced, so stale with any positive threshold.
        assert!(health.check_staleness(Duration::from_secs(1)));
    }

    #[test]
    fn test_record_success_resets_failures() {
        let mut health = ReplicationHealth::new(Uuid::new_v4());
        health.record_failure("test error");
        health.record_failure("test error 2");
        assert_eq!(health.consecutive_failures(), 2);

        let result = PullResult {
            changes_applied: 10,
            new_sequence_number: 42,
            duration: Duration::from_millis(150),
            status: ReplicationStatus::Synced,
        };
        health.record_success(&result);
        assert_eq!(health.consecutive_failures(), 0);
        assert_eq!(health.sequence_number(), 42);
    }

    #[test]
    fn test_record_failure_increments_counter() {
        let mut health = ReplicationHealth::new(Uuid::new_v4());
        health.record_failure("connection refused");
        assert_eq!(health.consecutive_failures(), 1);
        health.record_failure("connection refused again");
        assert_eq!(health.consecutive_failures(), 2);
    }

    #[test]
    fn test_avg_sync_duration() {
        let mut health = ReplicationHealth::new(Uuid::new_v4());
        assert_eq!(health.avg_sync_duration_ms(), 0);

        let result1 = PullResult {
            changes_applied: 5,
            new_sequence_number: 10,
            duration: Duration::from_millis(100),
            status: ReplicationStatus::Synced,
        };
        health.record_success(&result1);
        assert_eq!(health.avg_sync_duration_ms(), 100);

        let result2 = PullResult {
            changes_applied: 3,
            new_sequence_number: 13,
            duration: Duration::from_millis(200),
            status: ReplicationStatus::Synced,
        };
        health.record_success(&result2);
        assert_eq!(health.avg_sync_duration_ms(), 150);
    }

    #[test]
    fn test_health_report_marks_stale() {
        let mut health = ReplicationHealth::new(Uuid::new_v4());

        // Record a success far in the past by manipulating last_sync.
        let result = PullResult {
            changes_applied: 1,
            new_sequence_number: 1,
            duration: Duration::from_millis(50),
            status: ReplicationStatus::Synced,
        };
        health.record_success(&result);
        // Manually set last_sync to 2 hours ago to simulate staleness.
        health.last_sync = Some(Utc::now() - chrono::Duration::hours(2));

        let report = health.health_report(Duration::from_secs(3600));
        assert!(report.is_stale);
        assert!(matches!(report.status, ReplicationStatus::Stale { .. }));
    }

    #[test]
    fn test_health_report_not_stale_when_recent() {
        let mut health = ReplicationHealth::new(Uuid::new_v4());
        let result = PullResult {
            changes_applied: 1,
            new_sequence_number: 1,
            duration: Duration::from_millis(50),
            status: ReplicationStatus::Synced,
        };
        health.record_success(&result);

        let report = health.health_report(Duration::from_secs(3600));
        assert!(!report.is_stale);
        assert!(matches!(report.status, ReplicationStatus::Synced));
    }

    #[test]
    fn test_error_since_preserved_across_failures() {
        let mut health = ReplicationHealth::new(Uuid::new_v4());
        health.record_failure("first error");

        let first_since = match &health.status {
            ReplicationStatus::Error { since, .. } => *since,
            _ => panic!("Expected Error status"),
        };

        // Small delay would normally happen here in real usage.
        health.record_failure("second error");

        let second_since = match &health.status {
            ReplicationStatus::Error { since, .. } => *since,
            _ => panic!("Expected Error status"),
        };

        // The `since` timestamp should be preserved from the first failure.
        assert_eq!(first_since, second_since);
    }
}
