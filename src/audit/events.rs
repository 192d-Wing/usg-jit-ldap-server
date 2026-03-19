//! Audit event definitions.
//!
//! Each variant represents a security-relevant action that
//! gets serialized to the audit log.

use serde::Serialize;

/// A structured audit event.
#[derive(Debug, Serialize)]
pub enum AuditEvent {
    /// A client attempted to BIND.
    BindAttempt {
        source: String,
        dn: String,
        success: bool,
    },
    /// A client performed a SEARCH.
    Search {
        source: String,
        base_dn: String,
        filter: String,
    },
    /// A password was changed.
    PasswordChange {
        source: String,
        dn: String,
        success: bool,
    },
}

/// Emit an audit event to the configured sink.
pub fn emit(_event: AuditEvent) {
    // TODO: serialize and write to audit log
    todo!("audit event emission")
}
