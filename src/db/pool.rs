//! PostgreSQL connection pool management.
//!
//! Wraps `sqlx::PgPool` with configuration-driven setup
//! and health-check support.

use sqlx::PgPool;

/// Create a connection pool from the configured database URL.
pub async fn create_pool(
    database_url: &str,
    max_connections: u32,
) -> Result<PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await
}
