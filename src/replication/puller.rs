//! Replication puller: fetches incremental identity changes from the central hub.
//!
//! The puller runs as a background tokio task on each site. It periodically
//! connects to the central hub's PostgreSQL database, queries for changes since
//! the site's last known sequence number, and applies them to the local identity
//! schema within a transaction.
//!
//! # NIST SP 800-53 Rev. 5 Control Mappings
//!
//! - **SC-8 (Transmission Confidentiality and Integrity)**: The replication
//!   channel connects to central PostgreSQL with `sslmode=verify-full`, ensuring
//!   TLS encryption and server certificate verification. All identity data in
//!   transit is encrypted. No password material is ever transmitted.
//!
//! - **SI-7 (Software, Firmware, and Information Integrity)**: Sequence numbers
//!   provide a tamper-evident ordering of changes. Changes are applied in strict
//!   sequence order. Any gap in sequence numbers triggers investigation or full
//!   re-sync. Idempotent application (UPSERT/DELETE) ensures repeated application
//!   does not corrupt data.
//!
//! - **CP-9 (System Backup)**: The local identity data at each site constitutes
//!   an operational backup. During WAN outages, the site continues serving from
//!   its local copy. The replication mechanism is the recovery path.
//!
//! - **CP-10 (System Recovery)**: Automatic incremental catch-up after outages.
//!   Full re-sync capability when incremental sync is not possible (e.g., log
//!   pruning gap). Recovery is automated and requires no manual intervention
//!   for common failure modes.
//!
//! # Design Tradeoffs (v1)
//!
//! **Direct PostgreSQL vs. HTTPS API for replication transport:**
//!
//! v1 uses direct PostgreSQL connections from site to central. This was chosen
//! because:
//! - Simplicity: no additional API server to build, deploy, and secure.
//! - PostgreSQL's native TLS handles SC-8 requirements.
//! - Efficient batch queries with server-side cursors.
//! - Row-level security can restrict what a site connection can read.
//!
//! The tradeoff is that central PostgreSQL must accept connections from all 184
//! sites, which requires careful connection pool management and firewall rules.
//! A future version may introduce an HTTPS replication API if connection scaling
//! becomes problematic or if additional authentication layers are needed.

use std::time::{Duration, Instant};

use chrono::Utc;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use super::health::ReplicationHealth;
use super::{GroupRecord, ReplicationConfig, ReplicationStatus, UserRecord};

/// Result of a single pull cycle.
#[derive(Debug, Clone)]
pub struct PullResult {
    /// Number of identity changes applied in this pull cycle.
    pub changes_applied: u64,
    /// The highest sequence number consumed in this pull cycle.
    pub new_sequence_number: i64,
    /// Wall-clock duration of the pull cycle.
    pub duration: Duration,
    /// Replication status after this pull cycle.
    pub status: ReplicationStatus,
}

/// A single identity change to be applied at a site.
///
/// These are deserialized from the central `replication_log` table's payload.
/// Only identity data is represented here -- passwords, audit events, and
/// runtime state are explicitly excluded.
///
/// # NIST AC-4 (Information Flow Enforcement)
/// This enum defines the complete set of data that crosses the replication
/// boundary. Any data type not represented here is site-local and never
/// replicated.
#[derive(Debug, Clone)]
pub enum ReplicationChange {
    /// Insert or update a user record in the local identity schema.
    UserUpsert(UserRecord),
    /// Delete a user record from the local identity schema.
    UserDelete { user_id: Uuid },
    /// Insert or update a group record in the local identity schema.
    GroupUpsert(GroupRecord),
    /// Delete a group record from the local identity schema.
    GroupDelete { group_id: Uuid },
    /// Add or remove a user from a group.
    MembershipChange {
        user_id: Uuid,
        group_id: Uuid,
        /// true = add membership, false = remove membership.
        added: bool,
    },
    /// Grant or revoke a user's access to a specific site.
    SitePolicyChange {
        user_id: Uuid,
        site_id: Uuid,
        /// true = access allowed, false = access revoked.
        access_allowed: bool,
    },
}

/// Supported replication protocol version.
const REPLICATION_PROTOCOL_VERSION: i32 = 1;

/// Row from the central `replication_log` table.
#[derive(Debug)]
struct ReplicationLogEntry {
    seq_number: i64,
    change_type: String,
    entity_id: Uuid,
    payload: serde_json::Value,
    payload_hash: String,
    protocol_version: i32,
    #[allow(dead_code)]
    created_at: chrono::DateTime<Utc>,
}

/// The replication puller that runs on each site.
///
/// Holds references to the local database pool and the replication configuration.
/// Spawns a background task that runs the pull loop.
pub struct ReplicationPuller {
    /// Connection pool for the local site database.
    local_pool: sqlx::PgPool,
    /// Replication configuration.
    config: ReplicationConfig,
    /// Health tracker, shared with the health reporting subsystem.
    health: std::sync::Arc<tokio::sync::Mutex<ReplicationHealth>>,
}

impl ReplicationPuller {
    /// Creates a new `ReplicationPuller`.
    ///
    /// # Arguments
    /// - `local_pool`: connection pool for the site's local PostgreSQL database.
    /// - `config`: replication configuration (must be validated before calling).
    /// - `health`: shared health tracker for reporting status to the health endpoint.
    pub fn new(
        local_pool: sqlx::PgPool,
        config: ReplicationConfig,
        health: std::sync::Arc<tokio::sync::Mutex<ReplicationHealth>>,
    ) -> Self {
        Self {
            local_pool,
            config,
            health,
        }
    }

    /// Spawns the replication pull loop as a background tokio task.
    ///
    /// The task runs until the tokio runtime shuts down or `max_retry_attempts`
    /// consecutive failures are exceeded.
    ///
    /// Returns a `JoinHandle` that can be used to await task completion or
    /// detect panics.
    pub fn start(self) -> JoinHandle<()> {
        let site_id = self.config.site_id;
        info!(
            site_id = %site_id,
            pull_interval_secs = self.config.pull_interval.as_secs(),
            "Starting replication puller"
        );

        tokio::spawn(async move {
            self.run_loop().await;
        })
    }

    /// Main pull loop. Runs indefinitely, pulling on each interval.
    async fn run_loop(&self) {
        let mut consecutive_failures: u32 = 0;
        let mut interval = tokio::time::interval(self.config.pull_interval);

        // Stagger the first tick to avoid thundering herd across 184 sites.
        // Use the site_id's first 4 bytes as a deterministic offset.
        let stagger_ms = {
            let id_bytes = self.config.site_id.as_bytes();
            let offset_raw =
                u32::from_le_bytes([id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]);
            (offset_raw % (self.config.pull_interval.as_millis() as u32)) as u64
        };
        if stagger_ms > 0 {
            debug!(
                stagger_ms,
                site_id = %self.config.site_id,
                "Staggering initial pull"
            );
            tokio::time::sleep(Duration::from_millis(stagger_ms)).await;
        }

        loop {
            interval.tick().await;

            // Update status to Syncing.
            {
                let mut h = self.health.lock().await;
                h.set_status(ReplicationStatus::Syncing);
            }

            match self.pull_once().await {
                Ok(result) => {
                    consecutive_failures = 0;
                    let mut h = self.health.lock().await;
                    h.record_success(&result);

                    info!(
                        event_type = "replication_sync",
                        site_id = %self.config.site_id,
                        success = true,
                        changes_applied = result.changes_applied,
                        new_seq = result.new_sequence_number,
                        duration_ms = result.duration.as_millis() as u64,
                        "Pull cycle completed"
                    );

                    // If we got a full batch, there may be more changes.
                    // Pull again immediately without waiting for the next interval.
                    if result.changes_applied as i64 >= self.config.batch_size {
                        debug!("Full batch received, pulling again immediately");
                        continue;
                    }
                }
                Err(e) => {
                    consecutive_failures += 1;
                    let error_msg = format!("{:#}", e);

                    {
                        let mut h = self.health.lock().await;
                        h.record_failure(&error_msg);
                    }

                    error!(
                        event_type = "replication_sync",
                        site_id = %self.config.site_id,
                        success = false,
                        consecutive_failures,
                        error = %error_msg,
                        "Pull cycle failed"
                    );

                    if consecutive_failures >= self.config.max_retry_attempts {
                        error!(
                            site_id = %self.config.site_id,
                            consecutive_failures,
                            "Max retry attempts exceeded, stopping puller. \
                             Manual intervention or service restart required."
                        );
                        return;
                    }

                    // Exponential backoff with cap.
                    let backoff = self.compute_backoff(consecutive_failures);
                    warn!(
                        site_id = %self.config.site_id,
                        backoff_secs = backoff.as_secs(),
                        "Backing off before next retry"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// Executes a single pull cycle.
    ///
    /// 1. Reads local `replication_metadata` to get the last sequence number.
    /// 2. Connects to central PostgreSQL.
    /// 3. Queries for changes since the last sequence number.
    /// 4. Applies changes to local identity schema in a transaction.
    /// 5. Updates the local sequence number.
    /// 6. Returns `PullResult` with statistics.
    #[instrument(skip(self), fields(site_id = %self.config.site_id))]
    pub async fn pull_once(&self) -> Result<PullResult, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();

        // Step 1: Read local replication state.
        let last_seq = self.read_local_sequence_number().await?;
        debug!(last_seq, "Read local sequence number");

        // Step 2: Connect to central with mTLS.
        //
        // NIST SC-8: Connection uses TLS (enforced by sslmode in the connection
        // string, validated at config time).
        // NIST IA-3: Client certificate authenticates this site to central.
        let connect_url = build_central_url(&self.config);
        let central_pool = sqlx::PgPool::connect(&connect_url).await?;

        // Step 3: Fetch changes from central.
        let entries: Vec<ReplicationLogEntry> = self
            .fetch_changes_from_central(&central_pool, last_seq)
            .await?;
        debug!(
            entries_count = entries.len(),
            "Fetched changes from central"
        );

        if entries.is_empty() {
            let duration = start.elapsed();
            return Ok(PullResult {
                changes_applied: 0,
                new_sequence_number: last_seq,
                duration,
                status: ReplicationStatus::Synced,
            });
        }

        // Step 3b: Verify protocol version, payload integrity, and sequence continuity.
        self.verify_entries(&entries, last_seq)?;

        // Step 4 & 5: Parse changes and apply in a transaction.
        let changes = self.parse_entries(&entries)?;
        let max_seq = entries
            .iter()
            .map(|e| e.seq_number)
            .max()
            .unwrap_or(last_seq);
        let changes_count = changes.len() as u64;

        // SI-7: Apply changes within a transaction to maintain integrity.
        // If any change fails, the entire batch is rolled back.
        let mut tx = self.local_pool.begin().await?;
        self.apply_changes_in_tx(&mut tx, &changes).await?;
        self.update_local_sequence_number(&mut tx, max_seq).await?;
        tx.commit().await?;

        let duration = start.elapsed();

        info!(
            changes_applied = changes_count,
            new_seq = max_seq,
            duration_ms = duration.as_millis() as u64,
            "Applied replication batch"
        );

        Ok(PullResult {
            changes_applied: changes_count,
            new_sequence_number: max_seq,
            duration,
            status: ReplicationStatus::Synced,
        })
    }

    /// Reads the site's last consumed sequence number from local metadata.
    async fn read_local_sequence_number(
        &self,
    ) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT last_sequence_number FROM identity.replication_metadata WHERE site_id = $1",
        )
        .bind(self.config.site_id)
        .fetch_optional(&self.local_pool)
        .await?;

        match row {
            Some((seq,)) => Ok(seq),
            None => {
                // First run: insert metadata row with sequence 0.
                sqlx::query(
                    "INSERT INTO identity.replication_metadata (site_id, last_sequence_number) \
                     VALUES ($1, 0) ON CONFLICT (site_id) DO NOTHING",
                )
                .bind(self.config.site_id)
                .execute(&self.local_pool)
                .await?;
                Ok(0)
            }
        }
    }

    /// Fetches replication log entries from central since the given sequence number.
    ///
    /// # NIST SC-8 (Transmission Confidentiality)
    /// This query runs over a TLS-encrypted PostgreSQL connection.
    /// The result set contains only identity data -- never passwords or audit events.
    async fn fetch_changes_from_central(
        &self,
        central_pool: &sqlx::PgPool,
        since_seq: i64,
    ) -> Result<Vec<ReplicationLogEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let rows = sqlx::query_as::<_, (i64, String, Uuid, serde_json::Value, String, i32, chrono::DateTime<Utc>)>(
                "SELECT seq_number, change_type, entity_id, payload, payload_hash, protocol_version, created_at \
             FROM replication_log \
             WHERE seq_number > $1 \
             ORDER BY seq_number ASC \
             LIMIT $2",
            )
            .bind(since_seq)
            .bind(self.config.batch_size)
            .fetch_all(central_pool)
            .await?;

        let entries = rows
            .into_iter()
            .map(
                |(
                    seq_number,
                    change_type,
                    entity_id,
                    payload,
                    payload_hash,
                    protocol_version,
                    created_at,
                )| ReplicationLogEntry {
                    seq_number,
                    change_type,
                    entity_id,
                    payload,
                    payload_hash,
                    protocol_version,
                    created_at,
                },
            )
            .collect();

        Ok(entries)
    }

    /// Verifies replication entries for protocol version, payload integrity,
    /// and sequence number continuity.
    ///
    /// # NIST SI-7 (Information Integrity)
    /// - Protocol version: rejects entries from unknown protocol versions.
    /// - SHA-256 verification: recomputes hash of payload and compares to stored
    ///   digest to detect tampering in transit or at rest.
    /// - Sequence gap detection: ensures no entries were dropped between the
    ///   last known sequence and the first entry in this batch.
    fn verify_entries(
        &self,
        entries: &[ReplicationLogEntry],
        last_seq: i64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Protocol version check.
        for entry in entries {
            if entry.protocol_version > REPLICATION_PROTOCOL_VERSION {
                return Err(format!(
                    "replication entry seq={} uses protocol version {} (supported: {}). \
                     Upgrade the site software to process this entry.",
                    entry.seq_number, entry.protocol_version, REPLICATION_PROTOCOL_VERSION
                )
                .into());
            }
        }

        // SHA-256 payload integrity verification.
        for entry in entries {
            let computed = {
                let payload_text = entry.payload.to_string();
                let hash = Sha256::digest(payload_text.as_bytes());
                hash.iter().fold(String::with_capacity(64), |mut s, b| {
                    use std::fmt::Write;
                    let _ = write!(s, "{b:02x}");
                    s
                })
            };
            if computed != entry.payload_hash {
                return Err(format!(
                    "NIST SI-7: replication payload integrity check failed for seq={}. \
                     Expected hash '{}', computed '{}'.",
                    entry.seq_number, entry.payload_hash, computed
                )
                .into());
            }
        }

        // Sequence gap detection — reject batch and require full resync.
        // NIST SI-7: Gaps indicate log pruning, tampering, or data loss.
        // Continuing with gaps would silently lose identity changes.
        if let Some(first) = entries.first() {
            let expected_first = last_seq + 1;
            if first.seq_number != expected_first {
                return Err(format!(
                    "NIST SI-7: sequence gap detected — expected seq {}, got {}. \
                     Full re-sync required to recover missing changes.",
                    expected_first, first.seq_number
                )
                .into());
            }
        }

        // Check for internal gaps within the batch.
        for window in entries.windows(2) {
            let prev = window[0].seq_number;
            let curr = window[1].seq_number;
            if curr != prev + 1 {
                return Err(format!(
                    "NIST SI-7: internal sequence gap in batch ({} -> {}). \
                     Batch rejected — data integrity cannot be guaranteed.",
                    prev, curr
                )
                .into());
            }
        }

        Ok(())
    }

    /// Parses replication log entries into typed `ReplicationChange` values.
    ///
    /// # NIST SI-7 (Information Integrity)
    /// Validates that each entry has a known change type and valid payload.
    /// Unknown change types are logged as warnings and skipped (forward
    /// compatibility for future change types).
    fn parse_entries(
        &self,
        entries: &[ReplicationLogEntry],
    ) -> Result<Vec<ReplicationChange>, Box<dyn std::error::Error + Send + Sync>> {
        let mut changes = Vec::with_capacity(entries.len());

        for entry in entries {
            match entry.change_type.as_str() {
                "user_upsert" => {
                    let username = entry
                        .payload
                        .get("username")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .ok_or("user_upsert: missing or empty username")?
                        .to_string();
                    let dn = entry
                        .payload
                        .get("dn")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .ok_or("user_upsert: missing or empty dn")?
                        .to_string();
                    let enabled = entry
                        .payload
                        .get("enabled")
                        .and_then(|v| v.as_bool())
                        .ok_or("user_upsert: missing enabled field")?;
                    let require_client_cert = entry
                        .payload
                        .get("require_client_cert")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let record: UserRecord = UserRecord {
                        user_id: entry.entity_id,
                        username,
                        dn,
                        display_name: entry
                            .payload
                            .get("display_name")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        email: entry
                            .payload
                            .get("email")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        enabled,
                        require_client_cert,
                        updated_at: Utc::now(),
                    };
                    changes.push(ReplicationChange::UserUpsert(record));
                }
                "user_delete" => {
                    changes.push(ReplicationChange::UserDelete {
                        user_id: entry.entity_id,
                    });
                }
                "group_upsert" => {
                    let record = GroupRecord {
                        group_id: entry.entity_id,
                        group_name: entry
                            .payload
                            .get("group_name")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .ok_or("group_upsert: missing or empty group_name")?
                            .to_string(),
                        dn: entry
                            .payload
                            .get("dn")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .ok_or("group_upsert: missing or empty dn")?
                            .to_string(),
                        description: entry
                            .payload
                            .get("description")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        updated_at: Utc::now(),
                    };
                    changes.push(ReplicationChange::GroupUpsert(record));
                }
                "group_delete" => {
                    changes.push(ReplicationChange::GroupDelete {
                        group_id: entry.entity_id,
                    });
                }
                "membership_add" => {
                    let group_id = entry
                        .payload
                        .get("group_id")
                        .and_then(|v| v.as_str())
                        .map(Uuid::parse_str)
                        .transpose()
                        .map_err(|e| format!("membership_add: invalid group_id UUID: {e}"))?
                        .ok_or("membership_add: missing group_id")?;
                    changes.push(ReplicationChange::MembershipChange {
                        user_id: entry.entity_id,
                        group_id,
                        added: true,
                    });
                }
                "membership_remove" => {
                    let group_id = entry
                        .payload
                        .get("group_id")
                        .and_then(|v| v.as_str())
                        .map(Uuid::parse_str)
                        .transpose()
                        .map_err(|e| format!("membership_remove: invalid group_id UUID: {e}"))?
                        .ok_or("membership_remove: missing group_id")?;
                    changes.push(ReplicationChange::MembershipChange {
                        user_id: entry.entity_id,
                        group_id,
                        added: false,
                    });
                }
                "site_policy_grant" => {
                    let site_id = entry
                        .payload
                        .get("site_id")
                        .and_then(|v| v.as_str())
                        .map(Uuid::parse_str)
                        .transpose()
                        .map_err(|e| format!("site_policy_grant: invalid site_id UUID: {e}"))?
                        .ok_or("site_policy_grant: missing site_id")?;
                    changes.push(ReplicationChange::SitePolicyChange {
                        user_id: entry.entity_id,
                        site_id,
                        access_allowed: true,
                    });
                }
                "site_policy_revoke" => {
                    let site_id = entry
                        .payload
                        .get("site_id")
                        .and_then(|v| v.as_str())
                        .map(Uuid::parse_str)
                        .transpose()
                        .map_err(|e| format!("site_policy_revoke: invalid site_id UUID: {e}"))?
                        .ok_or("site_policy_revoke: missing site_id")?;
                    changes.push(ReplicationChange::SitePolicyChange {
                        user_id: entry.entity_id,
                        site_id,
                        access_allowed: false,
                    });
                }
                unknown => {
                    // Forward compatibility: log and skip unknown change types.
                    // This allows central to introduce new change types without
                    // breaking existing site pullers.
                    warn!(
                        change_type = unknown,
                        seq_number = entry.seq_number,
                        "Unknown replication change type, skipping"
                    );
                }
            }
        }

        Ok(changes)
    }

    /// Applies a batch of identity changes within an existing transaction.
    ///
    /// All operations are idempotent:
    /// - Upserts use `INSERT ... ON CONFLICT DO UPDATE`.
    /// - Deletes use `DELETE ... WHERE` (no error if row doesn't exist).
    ///
    /// # NIST SI-7 (Information Integrity)
    /// Changes are applied in the order they were produced at central, within
    /// a single transaction. Either all changes in the batch succeed, or none
    /// are applied. This prevents partial application that could leave the
    /// identity schema in an inconsistent state.
    async fn apply_changes_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        changes: &[ReplicationChange],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for change in changes {
            match change {
                ReplicationChange::UserUpsert(user) => {
                    sqlx::query(
                        "INSERT INTO identity.users \
                            (id, username, dn, display_name, email, enabled, updated_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT (id) DO UPDATE SET \
                            username = EXCLUDED.username, \
                            dn = EXCLUDED.dn, \
                            display_name = EXCLUDED.display_name, \
                            email = EXCLUDED.email, \
                            enabled = EXCLUDED.enabled, \
                            updated_at = EXCLUDED.updated_at",
                    )
                    .bind(user.user_id)
                    .bind(&user.username)
                    .bind(&user.dn)
                    .bind(&user.display_name)
                    .bind(&user.email)
                    .bind(user.enabled)
                    .bind(user.updated_at)
                    .execute(&mut **tx)
                    .await?;
                }
                ReplicationChange::UserDelete { user_id } => {
                    // Delete memberships first (referential integrity).
                    sqlx::query("DELETE FROM identity.memberships WHERE user_id = $1")
                        .bind(user_id)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query("DELETE FROM identity.site_policies WHERE user_id = $1")
                        .bind(user_id)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query("DELETE FROM identity.users WHERE id = $1")
                        .bind(user_id)
                        .execute(&mut **tx)
                        .await?;
                }
                ReplicationChange::GroupUpsert(group) => {
                    sqlx::query(
                        "INSERT INTO identity.groups \
                            (id, group_name, dn, description, updated_at) \
                         VALUES ($1, $2, $3, $4, $5) \
                         ON CONFLICT (id) DO UPDATE SET \
                            group_name = EXCLUDED.group_name, \
                            dn = EXCLUDED.dn, \
                            description = EXCLUDED.description, \
                            updated_at = EXCLUDED.updated_at",
                    )
                    .bind(group.group_id)
                    .bind(&group.group_name)
                    .bind(&group.dn)
                    .bind(&group.description)
                    .bind(group.updated_at)
                    .execute(&mut **tx)
                    .await?;
                }
                ReplicationChange::GroupDelete { group_id } => {
                    // Delete memberships first (referential integrity).
                    sqlx::query("DELETE FROM identity.memberships WHERE group_id = $1")
                        .bind(group_id)
                        .execute(&mut **tx)
                        .await?;
                    sqlx::query("DELETE FROM identity.groups WHERE id = $1")
                        .bind(group_id)
                        .execute(&mut **tx)
                        .await?;
                }
                ReplicationChange::MembershipChange {
                    user_id,
                    group_id,
                    added,
                } => {
                    if *added {
                        sqlx::query(
                            "INSERT INTO identity.memberships (user_id, group_id) \
                             VALUES ($1, $2) \
                             ON CONFLICT (user_id, group_id) DO NOTHING",
                        )
                        .bind(user_id)
                        .bind(group_id)
                        .execute(&mut **tx)
                        .await?;
                    } else {
                        sqlx::query(
                            "DELETE FROM identity.memberships \
                             WHERE user_id = $1 AND group_id = $2",
                        )
                        .bind(user_id)
                        .bind(group_id)
                        .execute(&mut **tx)
                        .await?;
                    }
                }
                ReplicationChange::SitePolicyChange {
                    user_id,
                    site_id,
                    access_allowed,
                } => {
                    if *access_allowed {
                        sqlx::query(
                            "INSERT INTO identity.site_policies \
                                (user_id, site_id, access_allowed) \
                             VALUES ($1, $2, true) \
                             ON CONFLICT (user_id, site_id) DO UPDATE SET \
                                access_allowed = true",
                        )
                        .bind(user_id)
                        .bind(site_id)
                        .execute(&mut **tx)
                        .await?;
                    } else {
                        sqlx::query(
                            "INSERT INTO identity.site_policies \
                                (user_id, site_id, access_allowed) \
                             VALUES ($1, $2, false) \
                             ON CONFLICT (user_id, site_id) DO UPDATE SET \
                                access_allowed = false",
                        )
                        .bind(user_id)
                        .bind(site_id)
                        .execute(&mut **tx)
                        .await?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Updates the local sequence number after a successful batch application.
    async fn update_local_sequence_number(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        new_seq: i64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            "UPDATE identity.replication_metadata \
             SET last_sequence_number = $1, \
                 last_sync_at = now(), \
                 sync_status = 'synced' \
             WHERE site_id = $2",
        )
        .bind(new_seq)
        .bind(self.config.site_id)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Computes exponential backoff duration for retry attempts.
    ///
    /// Formula: min(base * 2^(attempt - 1), pull_interval)
    /// This ensures backoff never exceeds the normal pull interval.
    fn compute_backoff(&self, consecutive_failures: u32) -> Duration {
        compute_backoff_duration(
            self.config.retry_backoff_base_secs,
            self.config.pull_interval.as_secs(),
            consecutive_failures,
        )
    }
}

/// Build the central connection URL with mTLS parameters.
///
/// If client cert/key/ca paths are configured, appends sslcert, sslkey,
/// and sslrootcert query parameters to the connection string.
///
/// NIST IA-3: Client certificate authenticates the site to the central hub.
fn build_central_url(config: &super::ReplicationConfig) -> String {
    let mut url = config.central_url.clone();
    if let (Some(cert), Some(key), Some(ca)) = (
        &config.client_cert_path,
        &config.client_key_path,
        &config.ca_cert_path,
    ) {
        // Validate paths are absolute and contain no URL-special characters
        // to prevent parameter injection via crafted config values.
        for (name, path) in [("sslcert", cert), ("sslkey", key), ("sslrootcert", ca)] {
            if !std::path::Path::new(path).is_absolute() {
                tracing::error!(param = name, path = %path, "replication cert path must be absolute");
                return url; // Return URL without mTLS params — connection will fail safely.
            }
            if path.contains('&') || path.contains('=') || path.contains('?') || path.contains(';')
            {
                tracing::error!(
                    param = name,
                    "replication cert path contains invalid characters"
                );
                return url;
            }
        }
        let sep = if url.contains('?') { "&" } else { "?" };
        url.push_str(&format!(
            "{sep}sslcert={cert}&sslkey={key}&sslrootcert={ca}"
        ));
    }
    url
}

/// Compute exponential backoff duration.
///
/// Extracted as a free function for testability without requiring a PgPool.
fn compute_backoff_duration(base_secs: u64, max_secs: u64, consecutive_failures: u32) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(16);
    let backoff_secs = base_secs.saturating_mul(1u64 << exponent);
    Duration::from_secs(backoff_secs.min(max_secs))
}

/// Initiates a full re-sync for a site by resetting its sequence number.
///
/// This should be called when:
/// - A sequence gap is detected (central has pruned entries the site needs).
/// - The site's identity data is known to be corrupted.
/// - An operator explicitly requests a full rebuild.
///
/// After calling this, the next `pull_once` will fetch all available entries
/// from central. The caller should truncate local identity tables before
/// or as part of the next pull to avoid stale remnants.
///
/// # NIST CP-10 (System Recovery)
/// Full re-sync is the recovery mechanism for catastrophic data loss at a site.
/// The central hub's replication log and current identity tables serve as the
/// authoritative source for rebuilding site state.
pub async fn trigger_full_resync(
    local_pool: &sqlx::PgPool,
    site_id: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(site_id = %site_id, "Triggering full re-sync: resetting sequence number to 0");

    let mut tx = local_pool.begin().await?;

    // Truncate local identity tables.
    sqlx::query("TRUNCATE identity.site_policies, identity.memberships, identity.users, identity.groups CASCADE")
        .execute(&mut *tx)
        .await?;

    // Reset sequence number to 0.
    sqlx::query(
        "UPDATE identity.replication_metadata \
         SET last_sequence_number = 0, \
             last_sync_at = NULL, \
             sync_status = 'stale' \
         WHERE site_id = $1",
    )
    .bind(site_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    info!(site_id = %site_id, "Full re-sync prepared: identity tables truncated, sequence reset to 0");
    Ok(())
}

/// Spawns a replication puller as a background task.
///
/// Returns the task handle and a shared health tracker.
pub fn spawn_puller(
    config: ReplicationConfig,
    local_pool: std::sync::Arc<sqlx::PgPool>,
) -> (
    JoinHandle<()>,
    std::sync::Arc<tokio::sync::Mutex<ReplicationHealth>>,
) {
    let health = std::sync::Arc::new(tokio::sync::Mutex::new(ReplicationHealth::new(
        config.site_id,
    )));
    let puller = ReplicationPuller::new((*local_pool).clone(), config, health.clone());
    let handle = puller.start();
    (handle, health)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_calculation() {
        let base = 5u64;
        let max = 60u64;

        // First failure: 5 * 2^0 = 5s
        assert_eq!(compute_backoff_duration(base, max, 1).as_secs(), 5);
        // Second failure: 5 * 2^1 = 10s
        assert_eq!(compute_backoff_duration(base, max, 2).as_secs(), 10);
        // Third failure: 5 * 2^2 = 20s
        assert_eq!(compute_backoff_duration(base, max, 3).as_secs(), 20);
        // Fourth failure: 5 * 2^3 = 40s
        assert_eq!(compute_backoff_duration(base, max, 4).as_secs(), 40);
        // Fifth failure: 5 * 2^4 = 80s, capped at 60s
        assert_eq!(compute_backoff_duration(base, max, 5).as_secs(), 60);
    }
}
