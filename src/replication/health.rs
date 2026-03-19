// SPDX-License-Identifier: TBD
//
// Replication health tracking stub for Runtime agent.
//
// The canonical implementation lives on feat/replication.
//
// NIST SI-4: Health tracking enables continuous monitoring of replication status.
// NIST CP-9: Health reports indicate when a site is operating on stale data.

use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::puller::PullResult;
use super::ReplicationStatus;

/// Tracks the health of replication at a single site.
#[derive(Debug)]
pub struct ReplicationHealth {
    site_id: Uuid,
    status: ReplicationStatus,
    last_sync: Option<DateTime<Utc>>,
    sequence_number: i64,
    consecutive_failures: u32,
    last_error: Option<String>,
    total_sync_duration_ms: u64,
    successful_sync_count: u64,
}

impl ReplicationHealth {
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

    pub fn status(&self) -> &ReplicationStatus {
        &self.status
    }

    pub fn set_status(&mut self, status: ReplicationStatus) {
        self.status = status;
    }

    pub fn sequence_number(&self) -> i64 {
        self.sequence_number
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn record_success(&mut self, result: &PullResult) {
        let now = Utc::now();
        self.last_sync = Some(now);
        self.sequence_number = result.new_sequence_number;
        self.consecutive_failures = 0;
        self.last_error = None;
        self.status = result.status.clone();

        let duration_ms = result.duration.as_millis() as u64;
        self.total_sync_duration_ms += duration_ms;
        self.successful_sync_count += 1;

        tracing::info!(
            site_id = %self.site_id,
            replication_sequence_number = self.sequence_number,
            replication_changes_applied = result.changes_applied,
            replication_pull_duration_ms = duration_ms,
            "replication.sync.success"
        );
    }

    pub fn record_failure(&mut self, error: &str) {
        self.consecutive_failures += 1;
        self.last_error = Some(error.to_string());

        let since = match &self.status {
            ReplicationStatus::Error { since, .. } => *since,
            _ => Utc::now(),
        };

        self.status = ReplicationStatus::Error {
            message: error.to_string(),
            since,
        };

        tracing::warn!(
            site_id = %self.site_id,
            replication_consecutive_failures = self.consecutive_failures,
            replication_last_error = error,
            "replication.sync.failure"
        );
    }

    pub fn check_staleness(&self, threshold: Duration) -> bool {
        match self.last_sync {
            Some(last) => {
                let elapsed = Utc::now()
                    .signed_duration_since(last)
                    .to_std()
                    .unwrap_or(Duration::MAX);
                elapsed > threshold
            }
            None => true,
        }
    }
}
