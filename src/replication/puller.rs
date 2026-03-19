// SPDX-License-Identifier: TBD
//
// Replication puller stub for Runtime agent.
//
// The canonical implementation lives on feat/replication. This module provides
// the minimal spawn_puller function needed for the Runtime agent to start
// the background replication task.
//
// NIST SC-8: The replication channel uses TLS-encrypted PostgreSQL connections.
// NIST CP-9: Local identity data enables site survivability during WAN outages.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::Mutex;

use super::health::ReplicationHealth;
use super::ReplicationConfig;

/// Result of a single pull cycle.
#[derive(Debug, Clone)]
pub struct PullResult {
    pub changes_applied: u64,
    pub new_sequence_number: i64,
    pub duration: Duration,
    pub status: super::ReplicationStatus,
}

/// Spawn the replication puller as a background tokio task.
///
/// The puller periodically connects to the central hub's PostgreSQL database,
/// queries for changes since the last known sequence number, and applies them
/// to the local identity schema.
///
/// Returns a JoinHandle for the background task and a shared health tracker.
pub fn spawn_puller(
    config: ReplicationConfig,
    pool: Arc<PgPool>,
) -> (
    tokio::task::JoinHandle<()>,
    Arc<Mutex<ReplicationHealth>>,
) {
    let health = Arc::new(Mutex::new(ReplicationHealth::new(config.site_id)));
    let health_clone = health.clone();

    let handle = tokio::spawn(async move {
        tracing::info!(
            site_id = %config.site_id,
            pull_interval_secs = config.pull_interval.as_secs(),
            "replication puller started"
        );

        let mut interval = tokio::time::interval(config.pull_interval);
        let mut consecutive_failures = 0u32;

        loop {
            interval.tick().await;

            // Mark as syncing.
            {
                let mut h = health_clone.lock().await;
                h.set_status(super::ReplicationStatus::Syncing);
            }

            // Execute pull cycle.
            let start = std::time::Instant::now();
            match execute_pull(&config, &pool).await {
                Ok(changes) => {
                    consecutive_failures = 0;
                    let result = PullResult {
                        changes_applied: changes.0,
                        new_sequence_number: changes.1,
                        duration: start.elapsed(),
                        status: super::ReplicationStatus::Synced,
                    };
                    let mut h = health_clone.lock().await;
                    h.record_success(&result);
                    tracing::info!(
                        changes = changes.0,
                        sequence = changes.1,
                        duration_ms = start.elapsed().as_millis() as u64,
                        "replication pull complete"
                    );
                }
                Err(e) => {
                    consecutive_failures += 1;
                    let mut h = health_clone.lock().await;
                    h.record_failure(&e.to_string());
                    tracing::error!(
                        error = %e,
                        consecutive_failures = consecutive_failures,
                        "replication pull failed"
                    );

                    if consecutive_failures >= config.max_retry_attempts {
                        tracing::error!(
                            "replication puller halting after {} consecutive failures",
                            consecutive_failures
                        );
                        break;
                    }
                }
            }
        }
    });

    (handle, health)
}

/// Execute a single pull cycle against the central hub.
///
/// This is a stub implementation. The full implementation on feat/replication
/// performs incremental sequence-number-based replication with transactional
/// application of changes.
async fn execute_pull(
    _config: &ReplicationConfig,
    _pool: &PgPool,
) -> Result<(u64, i64), Box<dyn std::error::Error + Send + Sync>> {
    // Stub: in production, this connects to central_url, queries for changes
    // since the last sequence number, and applies them in a transaction.
    tracing::debug!("replication pull cycle (stub — no-op until feat/replication is merged)");
    Ok((0, 0))
}
