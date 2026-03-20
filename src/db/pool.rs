//! PostgreSQL connection pool management.
//!
//! Wraps `sqlx::PgPool` with configuration-driven setup, migration execution,
//! and health-check support.
//!
//! NIST CM-6: configuration management — pool sizing and connection parameters
//! are externalized and validated at startup.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::{info, warn};

use super::DbResult;

/// Connection pool wrapper providing lifecycle management and health probes.
///
/// The pool is shared across all request handlers. Its configuration (max
/// connections, timeouts) is tuned per-site based on expected load.
#[derive(Clone)]
pub struct DbPool {
    pool: PgPool,
}

impl DbPool {
    /// Create a new connection pool.
    ///
    /// # Arguments
    /// * `database_url` — PostgreSQL connection string (must use TLS in production).
    /// * `max_connections` — Upper bound on concurrent connections.
    ///
    /// NIST CM-6: connection parameters are externalized configuration.
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

    /// Run all pending SQL migrations from the `migrations/` directory.
    ///
    /// Migrations are applied in filename order. Each migration runs in its own
    /// transaction. The identity schema must be created before the runtime schema
    /// because `runtime.ephemeral_passwords` references `identity.users`.
    pub async fn run_migrations(&self) -> DbResult<()> {
        info!("running database migrations");
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        info!("database migrations complete");
        Ok(())
    }

    /// Health check — verifies the pool can execute a trivial query.
    ///
    /// Used by Kubernetes liveness and readiness probes.
    /// Returns `true` if the database is reachable, `false` otherwise.
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

    /// Borrow the underlying `PgPool` for direct query execution.
    #[must_use]
    pub fn inner(&self) -> &PgPool {
        &self.pool
    }
}
