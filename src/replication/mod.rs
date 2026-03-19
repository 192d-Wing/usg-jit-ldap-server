//! Replication module for the USG JIT LDAP Server.
//!
//! Implements pull-based identity data replication from the central hub to site
//! replicas. Each site runs a `ReplicationPuller` that periodically fetches
//! incremental changes from central and applies them to the local identity schema.
//!
//! # Architecture
//!
//! - Hub-and-spoke topology: one central hub, 184 site replicas.
//! - Pull-based: sites initiate connections to central (firewall-friendly).
//! - Sequence-number-based: monotonic sequence numbers ensure ordering and
//!   enable incremental sync without timestamps.
//! - Transactional application: each batch of changes is applied atomically.
//!
//! # Data Scope
//!
//! **Replicated**: users, groups, memberships, site policies (identity schema).
//! **Never replicated**: passwords, bind events, audit data, runtime state.
//!
//! # NIST SP 800-53 Rev. 5 Control Mappings
//!
//! - **AC-4 (Information Flow Enforcement)**: Only identity data crosses trust
//!   boundaries. Password material and audit logs are never replicated.
//! - **CP-9 (System Backup)**: Local identity data provides operational continuity
//!   during WAN outages.
//! - **CP-10 (System Recovery)**: Incremental catch-up and full re-sync restore
//!   site data after failures.

pub mod health;
pub mod puller;

use std::time::Duration;
use uuid::Uuid;

/// Replication configuration for a site.
///
/// Loaded from the site's configuration file and validated at startup.
/// Controls the behavior of the `ReplicationPuller` and health monitoring.
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Whether replication is enabled. When false, the puller does not start.
    /// Central hub nodes set this to false; site nodes set it to true.
    pub enabled: bool,

    /// PostgreSQL connection string for the central hub's database.
    ///
    /// # NIST SC-8 (Transmission Confidentiality and Integrity)
    /// This connection string MUST use `sslmode=verify-full` to ensure
    /// TLS encryption and certificate verification on the replication channel.
    pub central_url: String,

    /// How often the puller attempts to sync with central.
    /// Default: 60 seconds. Sites stagger their actual pull time using
    /// an offset derived from their site_id to avoid thundering herd.
    pub pull_interval: Duration,

    /// Unique identifier for this site. Used in replication_metadata tracking
    /// and health reporting.
    pub site_id: Uuid,

    /// Maximum number of consecutive pull failures before the puller
    /// stops retrying and requires manual intervention or service restart.
    /// Default: 50 (with exponential backoff, this covers ~24 hours).
    pub max_retry_attempts: u32,

    /// Base duration (in seconds) for exponential backoff between retries.
    /// Actual delay = base * 2^(attempt - 1), capped at pull_interval.
    /// Default: 5 seconds.
    pub retry_backoff_base_secs: u64,

    /// Duration after which identity data is considered stale.
    /// When `now() - last_sync_at > stale_threshold`, the site reports
    /// a Stale health status and alerting thresholds are triggered.
    /// Default: 1 hour.
    pub stale_threshold: Duration,

    /// Maximum number of changes to fetch per pull cycle.
    /// Default: 1000.
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
    /// Validates the configuration, returning an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.central_url.is_empty() {
            return Err("central_url is required when replication is enabled".into());
        }
        if self.site_id.is_nil() {
            return Err("site_id must be set to a non-nil UUID".into());
        }
        if self.pull_interval.as_secs() < 10 {
            return Err("pull_interval must be at least 10 seconds".into());
        }
        if self.stale_threshold < self.pull_interval {
            return Err("stale_threshold must be >= pull_interval".into());
        }
        // NIST SC-8: Warn if the connection string does not enforce TLS.
        if !self.central_url.contains("sslmode=verify-full")
            && !self.central_url.contains("sslmode=verify-ca")
        {
            return Err(
                "central_url must use sslmode=verify-full or sslmode=verify-ca \
                 (NIST SC-8: transmission confidentiality)"
                    .into(),
            );
        }
        if self.batch_size < 1 || self.batch_size > 100_000 {
            return Err("batch_size must be between 1 and 100,000".into());
        }
        Ok(())
    }
}

/// Replication status for a site.
///
/// Reported by the health subsystem and exposed via the health endpoint.
/// Operators and monitoring systems use this to assess site data freshness.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationStatus {
    /// Site is fully synchronized with central. Last pull returned no new changes,
    /// or all changes have been applied and the site is within the staleness threshold.
    Synced,

    /// A pull cycle is currently in progress.
    Syncing,

    /// Site is behind central by a known amount. Identity data is still being
    /// served but may not reflect recent changes at central.
    ///
    /// # NIST CP-9 (System Backup)
    /// During Stale status, the site continues operating using its local copy
    /// of identity data, providing continuity of service.
    Stale {
        /// Timestamp of the last successful sync.
        last_sync: chrono::DateTime<chrono::Utc>,
        /// Number of sequence numbers the site is behind (estimated).
        behind_by: i64,
    },

    /// Replication has encountered an error and is not currently syncing.
    Error {
        /// Human-readable error description.
        message: String,
        /// When the error state began.
        since: chrono::DateTime<chrono::Utc>,
    },
}

impl std::fmt::Display for ReplicationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Synced => write!(f, "Synced"),
            Self::Syncing => write!(f, "Syncing"),
            Self::Stale {
                last_sync,
                behind_by,
            } => write!(
                f,
                "Stale (last sync: {}, behind by {} changes)",
                last_sync, behind_by
            ),
            Self::Error { message, since } => {
                write!(f, "Error since {}: {}", since, message)
            }
        }
    }
}

/// A record representing a user in the identity schema.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub user_id: Uuid,
    pub username: String,
    pub dn: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub enabled: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A record representing a group in the identity schema.
#[derive(Debug, Clone)]
pub struct GroupRecord {
    pub group_id: Uuid,
    pub group_name: String,
    pub dn: String,
    pub description: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_disabled() {
        let config = ReplicationConfig::default();
        assert!(!config.enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_enabled_config_requires_central_url() {
        let config = ReplicationConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_valid_enabled_config() {
        let config = ReplicationConfig {
            enabled: true,
            central_url: "postgresql://hub:5432/ldap?sslmode=verify-full".into(),
            site_id: Uuid::new_v4(),
            pull_interval: Duration::from_secs(60),
            stale_threshold: Duration::from_secs(3600),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rejects_insecure_connection() {
        let config = ReplicationConfig {
            enabled: true,
            central_url: "postgresql://hub:5432/ldap?sslmode=prefer".into(),
            site_id: Uuid::new_v4(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("sslmode=verify-full"));
    }

    #[test]
    fn test_replication_status_display() {
        assert_eq!(ReplicationStatus::Synced.to_string(), "Synced");
        assert_eq!(ReplicationStatus::Syncing.to_string(), "Syncing");
    }
}
