//! Runtime schema queries — site-local credential and audit operations.
//!
//! This module accesses ONLY the `runtime` schema. It contains ephemeral
//! password management, bind event recording, rate limiting, and audit
//! queue operations.
//!
//! NIST IA-5: password storage scope — all credential material in this
//! module is site-local. It is NEVER included in replication queries,
//! NEVER returned in Search results, and NEVER transmitted outside the
//! site boundary. This invariant is enforced by:
//!   1. Schema separation (`runtime` vs `identity`)
//!   2. Database role privileges (replication role has no access to `runtime`)
//!   3. Application query construction (this module, Search handler excluded)

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use super::DbResult;

// ────────────────────────────────────────────────────────────
// Data structs
// ────────────────────────────────────────────────────────────

/// An ephemeral password record issued by the JIT Broker.
///
/// NIST IA-5(6): the `password_hash` field is an Argon2id hash.
/// The plaintext password is never stored. The hash is never transmitted
/// outside the site.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EphemeralPassword {
    pub id: Uuid,
    pub user_id: Uuid,
    pub password_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issued_by: String,
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// A recorded Bind attempt for audit and rate-limiting purposes.
///
/// Note: `source_ip` is stored as a String rather than `IpAddr` because
/// sqlx maps PostgreSQL INET to `ipnetwork::IpNetwork`. We avoid the
/// extra dependency by converting at the boundary.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BindEvent {
    pub id: i64,
    pub user_dn: String,
    pub source_ip: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub attempted_at: DateTime<Utc>,
}

// ────────────────────────────────────────────────────────────
// Repository
// ────────────────────────────────────────────────────────────

/// Repository for runtime schema operations.
///
/// All data managed by this repository is site-local and ephemeral.
/// Nothing written here is ever replicated.
pub struct RuntimeRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> RuntimeRepository<'a> {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// Find the most recently issued, valid (non-expired, non-used, non-revoked)
    /// password for a user.
    ///
    /// This is the primary lookup during Bind: after resolving the user from
    /// the identity schema, we fetch the active credential from runtime.
    ///
    /// NIST IA-5: credential retrieval is scoped to a single site's runtime schema.
    pub async fn find_valid_password(
        &self,
        user_id: Uuid,
    ) -> DbResult<Option<EphemeralPassword>> {
        let password = sqlx::query_as::<_, EphemeralPassword>(
            r#"
            SELECT id, user_id, password_hash, issued_at, expires_at,
                   issued_by, used, used_at, revoked
            FROM runtime.ephemeral_passwords
            WHERE user_id = $1
              AND used = FALSE
              AND revoked = FALSE
              AND expires_at > now()
            ORDER BY issued_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(self.pool)
        .await?;

        Ok(password)
    }

    /// Store a new ephemeral password issued by the JIT Broker.
    ///
    /// The `hash` parameter must be a pre-computed Argon2id hash. This
    /// function does NOT accept or handle plaintext passwords.
    ///
    /// Returns the UUID of the newly created password record.
    pub async fn store_password(
        &self,
        user_id: Uuid,
        hash: String,
        issued_by: &str,
        ttl_secs: i64,
    ) -> DbResult<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO runtime.ephemeral_passwords
                (user_id, password_hash, issued_by, expires_at)
            VALUES
                ($1, $2, $3, now() + make_interval(secs => $4::double precision))
            RETURNING id
            "#,
        )
        .bind(user_id)
        .bind(&hash)
        .bind(issued_by)
        .bind(ttl_secs as f64)
        .fetch_one(self.pool)
        .await?;

        Ok(id)
    }

    /// Mark a password as used after a successful Bind.
    ///
    /// Once used, the password cannot be reused. The JIT Broker must
    /// issue a new credential for subsequent authentications.
    pub async fn mark_password_used(&self, password_id: Uuid) -> DbResult<()> {
        sqlx::query(
            r#"
            UPDATE runtime.ephemeral_passwords
            SET used = TRUE, used_at = now()
            WHERE id = $1
            "#,
        )
        .bind(password_id)
        .execute(self.pool)
        .await?;

        Ok(())
    }

    /// Revoke all active passwords for a user.
    ///
    /// Called when the JIT Broker signals credential revocation or when
    /// a security event requires immediate credential invalidation.
    ///
    /// Returns the number of passwords revoked.
    pub async fn revoke_passwords_for_user(&self, user_id: Uuid) -> DbResult<u64> {
        let result = sqlx::query(
            r#"
            UPDATE runtime.ephemeral_passwords
            SET revoked = TRUE
            WHERE user_id = $1
              AND used = FALSE
              AND revoked = FALSE
              AND expires_at > now()
            "#,
        )
        .bind(user_id)
        .execute(self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Record a Bind attempt (success or failure).
    ///
    /// NIST AU-3: content of audit records — captures who (user_dn),
    /// where (source_ip), when (now), and outcome (success/failure_reason).
    pub async fn record_bind_event(
        &self,
        user_dn: &str,
        source_ip: IpAddr,
        success: bool,
        failure_reason: Option<&str>,
    ) -> DbResult<()> {
        let source_ip_str = source_ip.to_string();
        sqlx::query(
            r#"
            INSERT INTO runtime.bind_events (user_dn, source_ip, success, failure_reason)
            VALUES ($1, $2::inet, $3, $4)
            "#,
        )
        .bind(user_dn)
        .bind(&source_ip_str)
        .bind(success)
        .bind(failure_reason)
        .execute(self.pool)
        .await?;

        Ok(())
    }

    /// Check whether a user DN has exceeded the rate limit.
    ///
    /// Uses a sliding window: if the window has expired, the counter resets.
    /// If the counter is within the window and exceeds `max_attempts`, the
    /// request should be rejected BEFORE hash computation.
    ///
    /// NIST AC-7: unsuccessful logon attempts — this check must happen
    /// before password hash retrieval to prevent CPU exhaustion attacks.
    ///
    /// Returns `true` if the request is ALLOWED, `false` if rate-limited.
    pub async fn check_rate_limit(
        &self,
        user_dn: &str,
        max_attempts: u32,
        window_secs: i64,
    ) -> DbResult<bool> {
        // Upsert the rate limit state: if the window has expired, reset;
        // otherwise increment the counter. Return the resulting count.
        let count = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO runtime.rate_limit_state (user_dn, attempt_count, window_start)
            VALUES ($1, 1, now())
            ON CONFLICT (user_dn) DO UPDATE
            SET
                attempt_count = CASE
                    WHEN runtime.rate_limit_state.window_start + make_interval(secs => $3::double precision) < now()
                    THEN 1
                    ELSE runtime.rate_limit_state.attempt_count + 1
                END,
                window_start = CASE
                    WHEN runtime.rate_limit_state.window_start + make_interval(secs => $3::double precision) < now()
                    THEN now()
                    ELSE runtime.rate_limit_state.window_start
                END
            RETURNING attempt_count
            "#,
        )
        .bind(user_dn)
        .bind(max_attempts as i32)
        .bind(window_secs as f64)
        .fetch_one(self.pool)
        .await?;

        Ok(count <= max_attempts as i32)
    }

    /// Enqueue a structured audit event for asynchronous forwarding.
    ///
    /// NIST AU-6: audit review — events are durably queued in the local
    /// database and forwarded to the central SIEM asynchronously.
    pub async fn enqueue_audit_event(
        &self,
        event_type: &str,
        event_data: JsonValue,
    ) -> DbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO runtime.audit_queue (event_type, event_data)
            VALUES ($1, $2)
            "#,
        )
        .bind(event_type)
        .bind(&event_data)
        .execute(self.pool)
        .await?;

        Ok(())
    }

    /// Delete expired, used, or revoked passwords older than the retention window.
    ///
    /// Called periodically by a background task. Returns the number of
    /// rows deleted.
    pub async fn cleanup_expired_passwords(&self) -> DbResult<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM runtime.ephemeral_passwords
            WHERE expires_at < now()
               OR (used = TRUE AND used_at < now() - INTERVAL '1 hour')
               OR (revoked = TRUE AND issued_at < now() - INTERVAL '1 hour')
            "#,
        )
        .execute(self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}

// ────────────────────────────────────────────────────────────
// Standalone cleanup functions
// ────────────────────────────────────────────────────────────

/// Delete forwarded audit events older than the retention period.
///
/// Events that have been successfully forwarded to the central SIEM no
/// longer need to reside in the local audit queue. This function removes
/// them once they exceed the configured retention window.
///
/// Returns the number of rows deleted.
pub async fn cleanup_forwarded_audit_events(
    pool: &PgPool,
    retention_days: u32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM runtime.audit_queue
        WHERE forwarded = TRUE
          AND forwarded_at < now() - make_interval(days => $1::int)
        "#,
    )
    .bind(retention_days as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete expired and used ephemeral passwords older than 24 hours.
///
/// Passwords that are expired, used, or revoked and older than 24 hours
/// are no longer needed for authentication or audit correlation.
///
/// Returns the number of rows deleted.
pub async fn cleanup_stale_passwords(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM runtime.ephemeral_passwords
        WHERE (used = TRUE OR revoked = TRUE OR expires_at < now())
          AND issued_at < now() - interval '24 hours'
        "#,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
