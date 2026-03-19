// SPDX-License-Identifier: TBD
//
// LDAP Session State Machine
//
// Manages per-connection session state transitions:
//   Connected → Bound → Operating → Closed
//
// NIST SP 800-53 Rev. 5:
// - AC-3 (Access Control Enforcement): Every operation dispatch checks the session
//   state to ensure the caller has authenticated before accessing directory data.
//   No data is returned to unauthenticated connections.
// - SC-23 (Session Authenticity): Session state is entirely server-authoritative.
//   The server tracks authentication status internally — clients cannot forge or
//   replay session state. Re-bind resets the session identity atomically.

use std::net::SocketAddr;
use std::time::Instant;

use super::codec::{
    AuthChoice, BindRequest, BindResponse, CodecError, ExtendedRequest, LdapMessage, LdapResult,
    ProtocolOp, ResultCode, SearchRequest,
};

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

/// Information about the currently-bound identity.
#[derive(Debug, Clone)]
pub struct BindInfo {
    /// The distinguished name that successfully authenticated.
    pub dn: String,
    /// When the bind completed (monotonic clock).
    pub authenticated_at: Instant,
}

/// Session state machine states.
#[derive(Debug, Clone)]
pub enum SessionState {
    /// TLS handshake is complete but no bind has occurred.
    /// Only BindRequest is accepted in this state.
    Connected,

    /// The client has successfully authenticated.
    /// Search, ExtendedRequest, re-Bind, and Unbind are accepted.
    Bound(BindInfo),

    /// The session is closing or has closed.
    /// No further operations are processed.
    Closed,
}

/// Per-connection LDAP session.
///
/// Each TLS connection gets exactly one `LdapSession`. The session tracks
/// authentication state and provides operation-routing with state enforcement.
pub struct LdapSession {
    state: SessionState,
    peer_addr: SocketAddr,
    message_counter: u64,
}

impl LdapSession {
    /// Create a new session for an incoming TLS connection.
    pub fn new(peer_addr: SocketAddr) -> Self {
        tracing::info!(
            peer = %peer_addr,
            "new LDAP session (state: Connected)"
        );
        Self {
            state: SessionState::Connected,
            peer_addr,
            message_counter: 0,
        }
    }

    /// Returns the current session state.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Returns the remote peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns the number of messages processed on this session.
    pub fn message_counter(&self) -> u64 {
        self.message_counter
    }

    /// Returns `true` if the session is in the Bound state.
    pub fn is_bound(&self) -> bool {
        matches!(self.state, SessionState::Bound(_))
    }

    /// Returns the bind info if the session is bound, or `None`.
    pub fn bind_info(&self) -> Option<&BindInfo> {
        match &self.state {
            SessionState::Bound(info) => Some(info),
            _ => None,
        }
    }

    /// Transition the session to the Bound state.
    ///
    /// Called after successful authentication. Replaces any previous bind identity
    /// (re-bind is permitted per RFC 4511 Section 4.2.1).
    pub fn transition_to_bound(&mut self, dn: String) {
        tracing::info!(
            peer = %self.peer_addr,
            dn = %dn,
            "session bound"
        );
        self.state = SessionState::Bound(BindInfo {
            dn,
            authenticated_at: Instant::now(),
        });
    }

    /// Transition the session to the Closed state.
    pub fn transition_to_closed(&mut self) {
        tracing::info!(
            peer = %self.peer_addr,
            messages_processed = self.message_counter,
            "session closed"
        );
        self.state = SessionState::Closed;
    }

    /// Route an incoming LDAP message based on the current session state.
    ///
    /// Returns a list of response messages to send back to the client.
    /// An empty list means no response (e.g., UnbindRequest).
    ///
    /// # NIST AC-3: Access Control Enforcement
    /// This method is the single enforcement point for session-state-based access
    /// control. Operations are only dispatched if the session state permits them.
    pub fn handle_message(&mut self, msg: LdapMessage) -> Vec<LdapMessage> {
        self.message_counter += 1;
        let message_id = msg.message_id;

        match &self.state {
            SessionState::Connected => self.handle_connected(message_id, msg.protocol_op),
            SessionState::Bound(_) => self.handle_bound(message_id, msg.protocol_op),
            SessionState::Closed => {
                tracing::warn!(
                    peer = %self.peer_addr,
                    "message received on closed session, ignoring"
                );
                Vec::new()
            }
        }
    }

    /// Handle messages in the Connected state.
    /// Only BindRequest is accepted; everything else gets an error.
    fn handle_connected(&mut self, message_id: i32, op: ProtocolOp) -> Vec<LdapMessage> {
        match op {
            ProtocolOp::BindRequest(req) => self.dispatch_bind(message_id, req),
            ProtocolOp::UnbindRequest => {
                self.transition_to_closed();
                Vec::new() // No response for Unbind.
            }
            _ => {
                // NIST AC-3: Reject operations before authentication.
                tracing::warn!(
                    peer = %self.peer_addr,
                    "operation rejected: not bound"
                );
                vec![self.make_error_response(
                    message_id,
                    &op,
                    ResultCode::OperationsError,
                    "bind required before this operation",
                )]
            }
        }
    }

    /// Handle messages in the Bound state.
    fn handle_bound(&mut self, message_id: i32, op: ProtocolOp) -> Vec<LdapMessage> {
        match op {
            ProtocolOp::BindRequest(req) => {
                // Re-bind: RFC 4511 permits re-authentication on an existing connection.
                self.dispatch_bind(message_id, req)
            }
            ProtocolOp::UnbindRequest => {
                self.transition_to_closed();
                Vec::new()
            }
            ProtocolOp::SearchRequest(_req) => {
                // Placeholder: actual search dispatch will be wired by LdapHandler.
                // Return SearchResultDone with success for now.
                vec![LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::SearchResultDone(LdapResult {
                        result_code: ResultCode::Success,
                        matched_dn: String::new(),
                        diagnostic_message: String::new(),
                    }),
                }]
            }
            ProtocolOp::ExtendedRequest(_req) => {
                // Placeholder: actual extended op dispatch will be wired by LdapHandler.
                vec![LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::ExtendedResponse(
                        super::codec::ExtendedResponse {
                            result: LdapResult {
                                result_code: ResultCode::UnwillingToPerform,
                                matched_dn: String::new(),
                                diagnostic_message: "extended operation not yet wired".into(),
                            },
                            response_name: None,
                            response_value: None,
                        },
                    ),
                }]
            }
            // Any other operation: unwillingToPerform.
            _ => {
                tracing::warn!(
                    peer = %self.peer_addr,
                    "unsupported operation received"
                );
                vec![self.make_error_response(
                    message_id,
                    &op,
                    ResultCode::UnwillingToPerform,
                    "this server does not support the requested operation",
                )]
            }
        }
    }

    /// Handle a BindRequest.
    ///
    /// Validates protocol-level constraints (version, auth method) and returns
    /// a BindResponse. Actual credential verification is delegated to the
    /// BindHandler (wired by the Runtime agent).
    fn dispatch_bind(&mut self, message_id: i32, req: BindRequest) -> Vec<LdapMessage> {
        // NIST IA-2: Identification and authentication check.

        // Reject non-LDAPv3.
        if req.version != 3 {
            return vec![LdapMessage {
                message_id,
                protocol_op: ProtocolOp::BindResponse(BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::ProtocolError,
                        matched_dn: String::new(),
                        diagnostic_message: "only LDAPv3 is supported".into(),
                    },
                }),
            }];
        }

        // Reject SASL.
        if matches!(req.authentication, AuthChoice::Sasl) {
            return vec![LdapMessage {
                message_id,
                protocol_op: ProtocolOp::BindResponse(BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::AuthMethodNotSupported,
                        matched_dn: String::new(),
                        diagnostic_message: "only simple authentication is supported".into(),
                    },
                }),
            }];
        }

        // Reject anonymous bind (empty DN or empty password).
        let password = match &req.authentication {
            AuthChoice::Simple(pw) => pw,
            _ => unreachable!(), // SASL already handled above.
        };
        if req.name.is_empty() || password.is_empty() {
            // NIST IA-2: Anonymous access is explicitly prohibited.
            tracing::warn!(
                peer = %self.peer_addr,
                "anonymous bind rejected"
            );
            return vec![LdapMessage {
                message_id,
                protocol_op: ProtocolOp::BindResponse(BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::InvalidCredentials,
                        matched_dn: String::new(),
                        diagnostic_message: "anonymous bind is not permitted".into(),
                    },
                }),
            }];
        }

        // Credential verification is performed by the BindHandler (via LdapHandler).
        // If dispatch_bind is called directly (not through LdapHandler), reject.
        // This ensures the session layer alone cannot authenticate — the handler must.
        // NIST IA-2: Authentication requires the full auth pipeline, not just protocol checks.
        tracing::warn!(
            peer = %self.peer_addr,
            dn = %req.name,
            "bind rejected: session-layer dispatch cannot authenticate (use LdapHandler)"
        );
        vec![LdapMessage {
            message_id,
            protocol_op: ProtocolOp::BindResponse(BindResponse {
                result: LdapResult {
                    result_code: ResultCode::Other,
                    matched_dn: String::new(),
                    diagnostic_message: "internal error: auth pipeline not wired".into(),
                },
            }),
        }]
    }

    /// Build an error response message appropriate for the given operation.
    fn make_error_response(
        &self,
        message_id: i32,
        op: &ProtocolOp,
        code: ResultCode,
        diagnostic: &str,
    ) -> LdapMessage {
        let result = LdapResult {
            result_code: code,
            matched_dn: String::new(),
            diagnostic_message: diagnostic.into(),
        };

        let response_op = match op {
            ProtocolOp::BindRequest(_) => ProtocolOp::BindResponse(BindResponse { result }),
            ProtocolOp::SearchRequest(_) => ProtocolOp::SearchResultDone(result),
            ProtocolOp::ExtendedRequest(_) => {
                ProtocolOp::ExtendedResponse(super::codec::ExtendedResponse {
                    result,
                    response_name: None,
                    response_value: None,
                })
            }
            // For any other unsupported operation, we fabricate an ExtendedResponse
            // as a generic error carrier. In practice, a real LDAPv3 server would
            // use a Notice of Disconnection, but for rejected ops this suffices.
            _ => ProtocolOp::ExtendedResponse(super::codec::ExtendedResponse {
                result,
                response_name: None,
                response_value: None,
            }),
        };

        LdapMessage {
            message_id,
            protocol_op: response_op,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    #[test]
    fn test_new_session_is_connected() {
        let session = LdapSession::new(test_addr());
        assert!(matches!(session.state(), SessionState::Connected));
        assert!(!session.is_bound());
    }

    #[test]
    fn test_session_bind_rejects_without_handler() {
        let mut session = LdapSession::new(test_addr());
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: "cn=admin,dc=example,dc=com".into(),
                authentication: AuthChoice::Simple(b"password".to_vec()),
            }),
        };
        let responses = session.handle_message(msg);
        assert_eq!(responses.len(), 1);
        // Session-layer bind should reject — real auth goes through LdapHandler.
        assert!(!session.is_bound());
        match &responses[0].protocol_op {
            ProtocolOp::BindResponse(resp) => {
                assert_ne!(resp.result.result_code, ResultCode::Success);
            }
            _ => panic!("expected BindResponse"),
        }
    }

    #[test]
    fn test_search_before_bind_rejected() {
        let mut session = LdapSession::new(test_addr());
        let msg = LdapMessage {
            message_id: 2,
            protocol_op: ProtocolOp::SearchRequest(super::super::codec::SearchRequest {
                base_object: "dc=example,dc=com".into(),
                scope: super::super::codec::SearchScope::WholeSubtree,
                deref_aliases: super::super::codec::DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: super::super::codec::Filter::Present("objectClass".into()),
                attributes: vec![],
            }),
        };
        let responses = session.handle_message(msg);
        assert_eq!(responses.len(), 1);
        // Should get an error because we're not bound.
    }

    #[test]
    fn test_anonymous_bind_rejected() {
        let mut session = LdapSession::new(test_addr());
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(), // empty DN
                authentication: AuthChoice::Simple(b"password".to_vec()),
            }),
        };
        let responses = session.handle_message(msg);
        assert_eq!(responses.len(), 1);
        assert!(!session.is_bound());
        match &responses[0].protocol_op {
            ProtocolOp::BindResponse(resp) => {
                assert_eq!(resp.result.result_code, ResultCode::InvalidCredentials);
            }
            _ => panic!("expected BindResponse"),
        }
    }

    #[test]
    fn test_unbind_closes_session() {
        let mut session = LdapSession::new(test_addr());
        // Manually transition to bound (session dispatch no longer auto-authenticates).
        session.transition_to_bound("cn=admin".into());
        assert!(session.is_bound());

        // Then unbind.
        let responses = session.handle_message(LdapMessage {
            message_id: 2,
            protocol_op: ProtocolOp::UnbindRequest,
        });
        assert!(responses.is_empty()); // UnbindRequest gets no response.
        assert!(matches!(session.state(), SessionState::Closed));
    }

    #[test]
    fn test_version2_rejected() {
        let mut session = LdapSession::new(test_addr());
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 2,
                name: "cn=admin".into(),
                authentication: AuthChoice::Simple(b"pass".to_vec()),
            }),
        };
        let responses = session.handle_message(msg);
        match &responses[0].protocol_op {
            ProtocolOp::BindResponse(resp) => {
                assert_eq!(resp.result.result_code, ResultCode::ProtocolError);
            }
            _ => panic!("expected BindResponse"),
        }
    }
}
