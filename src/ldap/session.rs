//! Per-connection LDAP session state.
//!
//! Tracks authentication status, message IDs, and enforces
//! protocol-level invariants for a single client connection.

/// Represents the state of a single LDAP client session.
pub struct LdapSession {
    /// Whether the client has completed a successful BIND.
    pub authenticated: bool,
    /// The DN the client is bound as, if any.
    pub bound_dn: Option<String>,
}

impl LdapSession {
    pub fn new() -> Self {
        Self {
            authenticated: false,
            bound_dn: None,
        }
    }
}
