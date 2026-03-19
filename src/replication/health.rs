//! Replication health checks.
//!
//! Exposes the last-successful-pull timestamp and lag metrics
//! so operators can monitor replication freshness.

use std::time::Instant;

/// Tracks replication health state.
pub struct ReplicationHealth {
    pub last_pull: Option<Instant>,
    pub last_error: Option<String>,
}

impl ReplicationHealth {
    pub fn new() -> Self {
        Self {
            last_pull: None,
            last_error: None,
        }
    }

    /// Returns true if replication is considered healthy.
    pub fn is_healthy(&self) -> bool {
        // TODO: check staleness against configured threshold
        self.last_pull.is_some() && self.last_error.is_none()
    }
}
