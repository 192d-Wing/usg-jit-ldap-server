//! Replication subsystem.
//!
//! Pulls identity data from a central authority on a
//! configurable interval, with health-check support.

pub mod health;
pub mod puller;
