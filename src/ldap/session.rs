// SPDX-License-Identifier: TBD
//
// LDAP Session State Machine
//
// Manages per-connection session state transitions:
//   Connected -> Bound -> Closed
//
// This is the Runtime agent's copy. The canonical implementation lives
// on feat/protocol. During integration merge, this file will be replaced.
//
// NIST SP 800-53 Rev. 5:
// - AC-3 (Access Control Enforcement): Every operation dispatch checks session
//   state to ensure the caller has authenticated before accessing directory data.
// - SC-23 (Session Authenticity): Session state is server-authoritative. Clients
//   cannot forge or replay session state.

use std::net::SocketAddr;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

/// Information about the currently-bound identity.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BindInfo {
    pub dn: String,
    pub authenticated_at: Instant,
}

/// Session state machine states.
#[derive(Debug, Clone)]
pub enum SessionState {
    Connected,
    Bound(BindInfo),
    Closed,
}

/// Per-connection LDAP session.
///
/// Each TLS connection gets exactly one LdapSession. The session tracks
/// authentication state and provides state-based access control.
pub struct LdapSession {
    state: SessionState,
    peer_addr: SocketAddr,
    message_counter: u64,
}

impl LdapSession {
    pub fn new(peer_addr: SocketAddr) -> Self {
        tracing::info!(peer = %peer_addr, "new LDAP session (state: Connected)");
        Self {
            state: SessionState::Connected,
            peer_addr,
            message_counter: 0,
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn message_counter(&self) -> u64 {
        self.message_counter
    }

    pub fn increment_counter(&mut self) {
        self.message_counter += 1;
    }

    pub fn is_bound(&self) -> bool {
        matches!(self.state, SessionState::Bound(_))
    }

    pub fn bind_info(&self) -> Option<&BindInfo> {
        match &self.state {
            SessionState::Bound(info) => Some(info),
            _ => None,
        }
    }

    pub fn transition_to_bound(&mut self, dn: String) {
        tracing::info!(peer = %self.peer_addr, dn = %dn, "session bound");
        self.state = SessionState::Bound(BindInfo {
            dn,
            authenticated_at: Instant::now(),
        });
    }

    pub fn transition_to_closed(&mut self) {
        tracing::info!(
            peer = %self.peer_addr,
            messages_processed = self.message_counter,
            "session closed"
        );
        self.state = SessionState::Closed;
    }
}
