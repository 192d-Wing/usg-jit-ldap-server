//! Shared test helpers for integration tests.
//!
//! These tests require a live PostgreSQL database. Set DATABASE_URL
//! environment variable to enable them. When DATABASE_URL is not set,
//! tests are skipped gracefully.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use sqlx::PgPool;
use uuid::Uuid;

/// Helper to get a test socket address.
pub fn test_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 54321)
}

/// Check if integration tests should run (DATABASE_URL is set).
pub fn should_run() -> bool {
    std::env::var("DATABASE_URL").is_ok()
}

/// Skip macro for integration tests when DB is unavailable.
#[macro_export]
macro_rules! skip_without_db {
    () => {
        if !common::should_run() {
            eprintln!("Skipping integration test: DATABASE_URL not set");
            return;
        }
    };
}

/// Create a PgPool from DATABASE_URL and run migrations.
pub async fn setup_test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&url)
        .await
        .expect("failed to connect to test DB");
    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("failed to run migrations");
    pool
}

/// Insert a test user into identity.users. Returns the user's UUID.
pub async fn insert_test_user(pool: &PgPool, dn: &str, username: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identity.users (id, username, display_name, email, dn, enabled, created_at, updated_at)
         VALUES ($1, $2, $2, $2 || '@test.com', $3, true, now(), now())
         ON CONFLICT (dn) DO UPDATE SET username = $2 RETURNING id",
    )
    .bind(id)
    .bind(username)
    .bind(dn)
    .execute(pool)
    .await
    .expect("failed to insert test user");
    id
}

/// Insert an ephemeral password for a user. Returns the password row UUID.
pub async fn insert_ephemeral_password(
    pool: &PgPool,
    user_id: Uuid,
    plaintext: &str,
    ttl_secs: i64,
) -> Uuid {
    // Hash the password using the project's own hash function
    let hash = usg_jit_ldap_server::auth::password::hash_password(plaintext.as_bytes().to_vec())
        .expect("failed to hash password");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO runtime.ephemeral_passwords (id, user_id, password_hash, issued_by, expires_at)
         VALUES ($1, $2, $3, 'test-harness', now() + make_interval(secs => $4::double precision))",
    )
    .bind(id)
    .bind(user_id)
    .bind(&hash)
    .bind(ttl_secs as f64)
    .execute(pool)
    .await
    .expect("failed to insert ephemeral password");
    id
}

/// Delete all test data from runtime and identity schemas.
pub async fn cleanup_test_data(pool: &PgPool) {
    // Clean runtime data first (no FK to identity)
    let _ = sqlx::query("DELETE FROM runtime.ephemeral_passwords")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM runtime.bind_events")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM runtime.rate_limit_state")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM runtime.audit_queue")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM runtime.search_rate_limit_state")
        .execute(pool)
        .await;
    // Clean identity data
    let _ = sqlx::query("DELETE FROM identity.memberships")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM identity.site_policies")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM identity.users")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM identity.groups")
        .execute(pool)
        .await;
}
