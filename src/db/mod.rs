//! Database access layer — separates replicated identity data from site-local runtime state.
//!
//! NIST SC-4: prevents information leakage between security domains.
//! The `identity` schema contains directory data replicated from the central hub.
//! The `runtime` schema contains ephemeral credentials and audit data that NEVER leave the site.
//!
//! This separation is enforced at the PostgreSQL schema level, the application query level,
//! and the replication configuration level. The replication role has no privileges on `runtime`.

pub mod identity;
pub mod pool;
pub mod runtime;

use thiserror::Error;

/// Database error type unifying sqlx errors with domain-specific failures.
#[derive(Debug, Error)]
pub enum DbError {
    /// Underlying database driver error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Migration execution failure.
    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// A query returned an unexpected number of rows.
    #[error("expected {expected} rows, got {actual}")]
    RowCount { expected: u64, actual: u64 },

    /// Domain constraint violation (e.g., invalid DN format).
    #[error("constraint violation: {0}")]
    Constraint(String),
}

/// Alias for Results using our database error type.
pub type DbResult<T> = Result<T, DbError>;
