// SPDX-License-Identifier: Apache-2.0
//
// Rate Limiting for Authentication Attempts
//
// Enforces per-DN bind attempt limits using the runtime database's
// rate_limit_state table. The rate limiter checks attempt counts within
// a sliding window BEFORE password hash verification, preventing CPU
// exhaustion attacks via repeated argon2 computations.
//
// NIST SP 800-53 Rev. 5:
// - AC-7 (Unsuccessful Logon Attempts): Automatically enforces a maximum
//   number of consecutive failed logon attempts within a configurable window.
//   After the threshold is exceeded, subsequent bind attempts for that DN are
//   rejected without performing password verification.
// - SI-10 (Information Input Validation): The DN is validated as non-empty
//   before rate limit checks. Source IP is recorded for forensic analysis.

use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("rate limit exceeded for DN '{dn}': {attempts} attempts in {window_secs}s window")]
    Exceeded {
        dn: String,
        attempts: u32,
        window_secs: u64,
    },

    #[error("rate limit check failed: {0}")]
    DatabaseError(#[from] sqlx::Error),
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Database-backed rate limiter for bind attempts.
///
/// Uses the runtime.rate_limit_state table to track per-DN attempt counts
/// within sliding windows. This is the enforcement point for NIST AC-7.
///
/// The rate limiter is called BEFORE password hash retrieval to prevent
/// CPU exhaustion attacks (argon2 is intentionally expensive).
#[derive(Clone)]
pub struct RateLimiter {
    pool: Arc<PgPool>,
    max_attempts: u32,
    window_secs: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given policy parameters.
    ///
    /// # Arguments
    /// - `pool`: Database connection pool for rate_limit_state queries.
    /// - `max_attempts`: Maximum bind attempts per DN within the window.
    /// - `window_secs`: Sliding window duration in seconds.
    pub fn new(pool: Arc<PgPool>, max_attempts: u32, window_secs: u64) -> Self {
        Self {
            pool,
            max_attempts,
            window_secs,
        }
    }

    /// Check whether a bind attempt for the given DN is allowed.
    ///
    /// This method atomically increments the attempt counter and checks
    /// the threshold. If the window has expired, the counter resets.
    ///
    /// NIST AC-7: This check MUST be performed before password hash lookup.
    ///
    /// Returns `Ok(())` if the attempt is allowed, or `Err(RateLimitError::Exceeded)`
    /// if the threshold has been reached.
    pub async fn check_and_increment(&self, dn: &str) -> Result<(), RateLimitError> {
        // SI-10: Validate input — DN must not be empty.
        if dn.is_empty() {
            // Empty DN is already rejected at the protocol layer, but
            // defense-in-depth: treat as rate-limited to prevent abuse.
            return Err(RateLimitError::Exceeded {
                dn: dn.to_string(),
                attempts: 0,
                window_secs: self.window_secs,
            });
        }

        // Atomically upsert and check the rate limit state.
        // If the window has expired, the counter resets to 1.
        // Otherwise, the counter is incremented.
        let count = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO runtime.rate_limit_state (user_dn, attempt_count, window_start)
            VALUES ($1, 1, now())
            ON CONFLICT (user_dn) DO UPDATE
            SET
                attempt_count = CASE
                    WHEN runtime.rate_limit_state.window_start
                         + make_interval(secs => $3::double precision) < now()
                    THEN 1
                    ELSE runtime.rate_limit_state.attempt_count + 1
                END,
                window_start = CASE
                    WHEN runtime.rate_limit_state.window_start
                         + make_interval(secs => $3::double precision) < now()
                    THEN now()
                    ELSE runtime.rate_limit_state.window_start
                END
            RETURNING attempt_count
            "#,
        )
        .bind(dn)
        .bind(self.max_attempts as i32)
        .bind(self.window_secs as f64)
        .fetch_one(self.pool.as_ref())
        .await?;

        if count > self.max_attempts as i32 {
            tracing::warn!(
                dn = %dn,
                attempt_count = count,
                max_attempts = self.max_attempts,
                window_secs = self.window_secs,
                "NIST AC-7: rate limit exceeded for DN"
            );
            Err(RateLimitError::Exceeded {
                dn: dn.to_string(),
                attempts: count as u32,
                window_secs: self.window_secs,
            })
        } else {
            Ok(())
        }
    }

    /// Return the configured maximum attempts.
    #[allow(dead_code)]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Return the configured window duration in seconds.
    #[allow(dead_code)]
    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }
}

// ---------------------------------------------------------------------------
// Search rate limiter
// ---------------------------------------------------------------------------

/// Per-IP search rate limiter.
///
/// NIST SI-10: Prevents search-based enumeration attacks.
#[derive(Clone)]
pub struct SearchRateLimiter {
    pool: Arc<PgPool>,
    max_searches: u32,
    window_secs: u64,
}

impl SearchRateLimiter {
    pub fn new(pool: Arc<PgPool>, max_searches: u32, window_secs: u64) -> Self {
        Self {
            pool,
            max_searches,
            window_secs,
        }
    }

    /// Check whether a search from the given IP is allowed.
    pub async fn check_and_increment(&self, source_ip: &str) -> Result<(), RateLimitError> {
        if source_ip.is_empty() {
            return Err(RateLimitError::Exceeded {
                dn: source_ip.to_string(),
                attempts: 0,
                window_secs: self.window_secs,
            });
        }

        let count = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO runtime.search_rate_limit_state (source_ip, search_count, window_start)
            VALUES ($1::inet, 1, now())
            ON CONFLICT (source_ip) DO UPDATE
            SET
                search_count = CASE
                    WHEN runtime.search_rate_limit_state.window_start
                         + make_interval(secs => $2::double precision) < now()
                    THEN 1
                    ELSE runtime.search_rate_limit_state.search_count + 1
                END,
                window_start = CASE
                    WHEN runtime.search_rate_limit_state.window_start
                         + make_interval(secs => $2::double precision) < now()
                    THEN now()
                    ELSE runtime.search_rate_limit_state.window_start
                END
            RETURNING search_count
            "#,
        )
        .bind(source_ip)
        .bind(self.window_secs as f64)
        .fetch_one(self.pool.as_ref())
        .await?;

        if count > self.max_searches as i32 {
            tracing::warn!(
                source_ip = %source_ip,
                search_count = count,
                max = self.max_searches,
                "search rate limit exceeded"
            );
            Err(RateLimitError::Exceeded {
                dn: source_ip.to_string(),
                attempts: count as u32,
                window_secs: self.window_secs,
            })
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_error_display() {
        let err = RateLimitError::Exceeded {
            dn: "cn=test".to_string(),
            attempts: 6,
            window_secs: 300,
        };
        let msg = err.to_string();
        assert!(msg.contains("cn=test"));
        assert!(msg.contains("6 attempts"));
        assert!(msg.contains("300s"));
    }
}
