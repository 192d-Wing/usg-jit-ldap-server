// SPDX-License-Identifier: TBD
//
// Replication module stub for Runtime agent.
//
// The canonical implementation lives on feat/replication. This module provides
// the minimal types needed for the Runtime agent to start the replication
// puller as a background task.
//
// NIST SP 800-53 Rev. 5:
// - AC-4 (Information Flow Enforcement): Only identity data crosses trust
//   boundaries. Password material is never replicated.
// - CP-9 (System Backup): Local identity data provides continuity during WAN outages.

// Replication types are stubs matching feat/replication interfaces.
// Not all fields/methods are used by the Runtime agent's startup code.
#[allow(dead_code)]
pub mod health;
pub mod puller;

use std::time::Duration;
use uuid::Uuid;

/// Replication configuration for a site.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ReplicationConfig {
    pub enabled: bool,
    pub central_url: String,
    pub pull_interval: Duration,
    pub site_id: Uuid,
    pub max_retry_attempts: u32,
    pub retry_backoff_base_secs: u64,
    pub stale_threshold: Duration,
    pub batch_size: i64,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            central_url: String::new(),
            pull_interval: Duration::from_secs(60),
            site_id: Uuid::nil(),
            max_retry_attempts: 50,
            retry_backoff_base_secs: 5,
            stale_threshold: Duration::from_secs(3600),
            batch_size: 1000,
        }
    }
}

impl ReplicationConfig {
    /// Build a ReplicationConfig from the server configuration.
    pub fn from_settings(settings: &crate::config::ReplicationSettings) -> Self {
        let site_id = settings
            .site_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or(Uuid::nil());

        Self {
            enabled: settings.enabled,
            central_url: settings.central_url.clone().unwrap_or_default(),
            pull_interval: Duration::from_secs(settings.pull_interval_secs),
            site_id,
            max_retry_attempts: settings.max_retry_attempts,
            retry_backoff_base_secs: 5,
            stale_threshold: Duration::from_secs(settings.stale_threshold_secs),
            batch_size: settings.batch_size,
        }
    }
}

/// Replication status.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum ReplicationStatus {
    Synced,
    Syncing,
    Stale {
        last_sync: chrono::DateTime<chrono::Utc>,
        behind_by: i64,
    },
    Error {
        message: String,
        since: chrono::DateTime<chrono::Utc>,
    },
}

impl std::fmt::Display for ReplicationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Synced => write!(f, "Synced"),
            Self::Syncing => write!(f, "Syncing"),
            Self::Stale { last_sync, behind_by } => {
                write!(f, "Stale (last sync: {}, behind by {} changes)", last_sync, behind_by)
            }
            Self::Error { message, since } => {
                write!(f, "Error since {}: {}", since, message)
            }
        }
    }
}
