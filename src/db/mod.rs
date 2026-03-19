// SPDX-License-Identifier: TBD
//
// Database access layer stub for Runtime agent.
//
// The canonical implementation lives on feat/data. This module provides
// the DbPool wrapper used by the Runtime agent's wiring code.
//
// NIST SC-4: Prevents information leakage between security domains.
// The identity schema contains replicated directory data.
// The runtime schema contains ephemeral credentials that NEVER leave the site.

pub mod pool;

use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("expected {expected} rows, got {actual}")]
    RowCount { expected: u64, actual: u64 },

    #[error("constraint violation: {0}")]
    Constraint(String),
}

pub type DbResult<T> = Result<T, DbError>;
