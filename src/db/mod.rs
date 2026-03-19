//! Database access layer.
//!
//! Manages the PostgreSQL connection pool and provides typed
//! access to the identity and runtime schemas.

pub mod identity;
pub mod pool;
pub mod runtime;
