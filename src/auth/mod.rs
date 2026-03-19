//! Authentication and rate-limiting layer.
//!
//! Provides password verification (argon2) and per-source
//! rate limiting for BIND attempts.

pub mod password;
pub mod rate_limit;
