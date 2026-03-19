// SPDX-License-Identifier: TBD
//
// LDAP Module Root
//
// Re-exports all LDAP protocol submodules and provides the top-level
// `LdapHandler` that routes incoming messages through the session state
// machine to the appropriate operation handlers.

pub mod bind;
pub mod codec;
pub mod password;
pub mod search;
pub mod session;

use codec::{
    ExtendedResponse, LdapMessage, LdapResult, ProtocolOp, ResultCode,
};
use session::LdapSession;

use bind::{Authenticator, BindHandler};
use password::{BrokerAuthorizer, PasswordModifyHandler, PasswordStore, PASSWORD_MODIFY_OID};
use search::{SearchBackend, SearchHandler};

// ---------------------------------------------------------------------------
// Top-level LDAP handler
// ---------------------------------------------------------------------------

/// Top-level LDAP message handler.
///
/// Routes decoded LDAPv3 messages through the session state machine and
/// dispatches them to the appropriate operation handler (Bind, Search,
/// Password Modify).
///
/// The `LdapHandler` is parameterized over its backend traits so the
/// Runtime agent can wire in the real implementations (PostgreSQL-backed
/// authenticator, search backend, and password store).
pub struct LdapHandler<A, B, S, Z>
where
    A: Authenticator,
    B: SearchBackend,
    S: PasswordStore,
    Z: BrokerAuthorizer,
{
    bind_handler: BindHandler<A>,
    search_handler: SearchHandler<B>,
    password_handler: PasswordModifyHandler<S, Z>,
}

impl<A, B, S, Z> LdapHandler<A, B, S, Z>
where
    A: Authenticator,
    B: SearchBackend,
    S: PasswordStore,
    Z: BrokerAuthorizer,
{
    /// Create a new `LdapHandler` with the given backend implementations.
    pub fn new(
        authenticator: A,
        search_backend: B,
        password_store: S,
        broker_authorizer: Z,
    ) -> Self {
        Self {
            bind_handler: BindHandler::new(authenticator),
            search_handler: SearchHandler::new(search_backend),
            password_handler: PasswordModifyHandler::new(password_store, broker_authorizer),
        }
    }

    /// Process an incoming LDAP message within the context of a session.
    ///
    /// Returns a list of response messages to send back to the client.
    /// The list may contain multiple messages (e.g., SearchResultEntry
    /// messages followed by SearchResultDone).
    ///
    /// An empty list means no response should be sent (e.g., UnbindRequest).
    pub async fn process_message(
        &self,
        session: &mut LdapSession,
        msg: LdapMessage,
    ) -> Vec<LdapMessage> {
        let message_id = msg.message_id;

        // Check session state for operations that need special handling.
        match &session.state() {
            session::SessionState::Closed => {
                tracing::warn!(
                    peer = %session.peer_addr(),
                    "message on closed session, ignoring"
                );
                return Vec::new();
            }
            session::SessionState::Connected => {
                // Only BindRequest and UnbindRequest are allowed before binding.
                match msg.protocol_op {
                    ProtocolOp::BindRequest(ref _req) => {
                        // Fall through to dispatch below.
                    }
                    ProtocolOp::UnbindRequest => {
                        session.transition_to_closed();
                        return Vec::new();
                    }
                    _ => {
                        // NIST AC-3: Reject everything else before authentication.
                        return vec![make_error_response(
                            message_id,
                            ResultCode::OperationsError,
                            "bind required before this operation",
                        )];
                    }
                }
            }
            session::SessionState::Bound(_) => {
                // All supported operations are allowed. Fall through.
            }
        }

        // Dispatch based on operation type.
        match msg.protocol_op {
            ProtocolOp::BindRequest(req) => {
                let resp = self.bind_handler.handle_bind(&req, session).await;
                vec![LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::BindResponse(resp),
                }]
            }
            ProtocolOp::UnbindRequest => {
                session.transition_to_closed();
                Vec::new()
            }
            ProtocolOp::SearchRequest(req) => {
                let (entries, result) =
                    self.search_handler.handle_search(&req, session).await;

                let mut responses: Vec<LdapMessage> = entries
                    .into_iter()
                    .map(|entry| LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::SearchResultEntry(entry),
                    })
                    .collect();

                responses.push(LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::SearchResultDone(result),
                });

                responses
            }
            ProtocolOp::ExtendedRequest(req) => {
                if req.request_name == PASSWORD_MODIFY_OID {
                    let resp = self
                        .password_handler
                        .handle_password_modify(&req, session)
                        .await;
                    vec![LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::ExtendedResponse(resp),
                    }]
                } else {
                    // Unknown extended operation — unwillingToPerform.
                    tracing::warn!(
                        peer = %session.peer_addr(),
                        oid = %req.request_name,
                        "unsupported extended operation"
                    );
                    vec![LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::ExtendedResponse(ExtendedResponse {
                            result: LdapResult {
                                result_code: ResultCode::UnwillingToPerform,
                                matched_dn: String::new(),
                                diagnostic_message: format!(
                                    "unsupported extended operation: {}",
                                    req.request_name
                                ),
                            },
                            response_name: None,
                            response_value: None,
                        }),
                    }]
                }
            }
            // Any other operation — unwillingToPerform.
            _ => {
                tracing::warn!(
                    peer = %session.peer_addr(),
                    "unsupported protocol operation"
                );
                vec![make_error_response(
                    message_id,
                    ResultCode::UnwillingToPerform,
                    "this server does not support the requested operation",
                )]
            }
        }
    }
}

/// Build a generic error response as an ExtendedResponse.
///
/// For operations where we don't have a specific response type
/// (e.g., unknown operations), we use an ExtendedResponse as a
/// catch-all error carrier.
fn make_error_response(message_id: i32, code: ResultCode, diagnostic: &str) -> LdapMessage {
    LdapMessage {
        message_id,
        protocol_op: ProtocolOp::ExtendedResponse(ExtendedResponse {
            result: LdapResult {
                result_code: code,
                matched_dn: String::new(),
                diagnostic_message: diagnostic.into(),
            },
            response_name: None,
            response_value: None,
        }),
    }
}

// ---------------------------------------------------------------------------
// Convenience type alias for the placeholder wiring
// ---------------------------------------------------------------------------

/// A fully-wired `LdapHandler` using placeholder backends.
/// Useful for testing and development.
pub type PlaceholderLdapHandler = LdapHandler<
    bind::PlaceholderAuthenticator,
    search::PlaceholderSearchBackend,
    password::PlaceholderPasswordStore,
    password::StaticBrokerAuthorizer,
>;

/// Create a placeholder `LdapHandler` for testing.
pub fn placeholder_handler() -> PlaceholderLdapHandler {
    LdapHandler::new(
        bind::PlaceholderAuthenticator,
        search::PlaceholderSearchBackend,
        password::PlaceholderPasswordStore,
        password::StaticBrokerAuthorizer {
            authorized_dns: vec!["cn=broker,ou=services,dc=example,dc=com".into()],
        },
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{AuthChoice, BindRequest, DerefAliases, Filter, SearchScope};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    #[tokio::test]
    async fn test_full_bind_search_flow() {
        let handler = placeholder_handler();
        let mut session = LdapSession::new(test_addr());

        // Bind.
        let bind_msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: "cn=admin,dc=example,dc=com".into(),
                authentication: AuthChoice::Simple(b"secret".to_vec()),
            }),
        };
        let responses = handler.process_message(&mut session, bind_msg).await;
        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            ProtocolOp::BindResponse(resp) => {
                assert_eq!(resp.result.result_code, ResultCode::Success);
            }
            _ => panic!("expected BindResponse"),
        }
        assert!(session.is_bound());

        // Search.
        let search_msg = LdapMessage {
            message_id: 2,
            protocol_op: ProtocolOp::SearchRequest(codec::SearchRequest {
                base_object: "dc=example,dc=com".into(),
                scope: SearchScope::WholeSubtree,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::Present("objectClass".into()),
                attributes: vec![],
            }),
        };
        let responses = handler.process_message(&mut session, search_msg).await;
        // Placeholder returns 0 entries + SearchResultDone.
        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            ProtocolOp::SearchResultDone(result) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            _ => panic!("expected SearchResultDone"),
        }
    }

    #[tokio::test]
    async fn test_search_before_bind_rejected() {
        let handler = placeholder_handler();
        let mut session = LdapSession::new(test_addr());
        let search_msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::SearchRequest(codec::SearchRequest {
                base_object: "dc=example,dc=com".into(),
                scope: SearchScope::BaseObject,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::Present("objectClass".into()),
                attributes: vec![],
            }),
        };
        let responses = handler.process_message(&mut session, search_msg).await;
        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            ProtocolOp::ExtendedResponse(resp) => {
                assert_eq!(resp.result.result_code, ResultCode::OperationsError);
            }
            _ => panic!("expected error response"),
        }
    }

    #[tokio::test]
    async fn test_unbind_closes_session() {
        let handler = placeholder_handler();
        let mut session = LdapSession::new(test_addr());

        // Bind first.
        handler
            .process_message(
                &mut session,
                LdapMessage {
                    message_id: 1,
                    protocol_op: ProtocolOp::BindRequest(BindRequest {
                        version: 3,
                        name: "cn=admin".into(),
                        authentication: AuthChoice::Simple(b"pass".to_vec()),
                    }),
                },
            )
            .await;

        // Unbind.
        let responses = handler
            .process_message(
                &mut session,
                LdapMessage {
                    message_id: 2,
                    protocol_op: ProtocolOp::UnbindRequest,
                },
            )
            .await;
        assert!(responses.is_empty());
        assert!(matches!(
            session.state(),
            session::SessionState::Closed
        ));
    }

    #[tokio::test]
    async fn test_unknown_extended_op_rejected() {
        let handler = placeholder_handler();
        let mut session = LdapSession::new(test_addr());
        // Bind.
        handler
            .process_message(
                &mut session,
                LdapMessage {
                    message_id: 1,
                    protocol_op: ProtocolOp::BindRequest(BindRequest {
                        version: 3,
                        name: "cn=admin".into(),
                        authentication: AuthChoice::Simple(b"pass".to_vec()),
                    }),
                },
            )
            .await;

        // Unknown extended op.
        let responses = handler
            .process_message(
                &mut session,
                LdapMessage {
                    message_id: 2,
                    protocol_op: ProtocolOp::ExtendedRequest(codec::ExtendedRequest {
                        request_name: "1.2.3.4.5.99".into(),
                        request_value: None,
                    }),
                },
            )
            .await;
        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            ProtocolOp::ExtendedResponse(resp) => {
                assert_eq!(resp.result.result_code, ResultCode::UnwillingToPerform);
            }
            _ => panic!("expected ExtendedResponse"),
        }
    }
}
