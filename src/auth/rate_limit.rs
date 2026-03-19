//! Rate limiting for authentication attempts.
//!
//! Tracks failed BIND attempts per source address and blocks
//! further attempts once the configured threshold is exceeded
//! within the sliding window.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Tracks BIND attempt counts per source IP.
pub struct RateLimiter {
    attempts: HashMap<IpAddr, Vec<Instant>>,
    max_attempts: u32,
    window_secs: u64,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window_secs,
        }
    }

    /// Returns `true` if the source is allowed to attempt a BIND.
    pub fn check(&mut self, _source: IpAddr) -> bool {
        // TODO: prune expired entries, check count
        todo!("rate limit check")
    }

    /// Record a failed BIND attempt from the given source.
    pub fn record_failure(&mut self, _source: IpAddr) {
        // TODO: append timestamp
        todo!("record failure")
    }
}
