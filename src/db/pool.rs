// SPDX-License-Identifier: TBD
//
// PostgreSQL connection pool management.
//
// Wraps sqlx::PgPool with configuration-driven setup, migration execution,
// and health-check support.
//
// NIST CM-6: Pool sizing and connection parameters are externalized and
// validated at startup.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::{info, warn};

use super::DbResult;

/// Connection pool wrapper.
#[derive(Clone)]
pub struct DbPool {
    pool: PgPool,
}

impl DbPool {
    /// Create a new connection pool.
    ///
    /// NIST CM-6: Connection parameters are externalized configuration.
    pub async fn connect(database_url: &str, max_connections: u32) -> DbResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await?;

        info!(
            max_connections = max_connections,
            "database connection pool established"
        );

        Ok(Self { pool })
    }

    /// Run all pending SQL migrations.
    pub async fn run_migrations(&self) -> DbResult<()> {
        info!("running database migrations");
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        info!("database migrations complete");
        Ok(())
    }

    /// Health check — verifies the pool can execute a trivial query.
    #[allow(dead_code)]
    pub async fn health_check(&self) -> bool {
        match sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "database health check failed");
                false
            }
        }
    }

    /// Borrow the underlying PgPool.
    pub fn inner(&self) -> &PgPool {
        &self.pool
    }
}
