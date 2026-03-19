//! Shared test helpers for integration tests.
//!
//! These tests require a live PostgreSQL database. Set DATABASE_URL
//! environment variable to enable them. When DATABASE_URL is not set,
//! tests are skipped gracefully.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
