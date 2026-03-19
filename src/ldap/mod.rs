// SPDX-License-Identifier: TBD
//
// LDAP Module Root
//
// Re-exports all LDAP protocol submodules and provides the top-level
// LdapHandler that routes incoming messages through the session state
// machine to the appropriate operation handlers.
//
// This is the Runtime agent's copy. The canonical LdapHandler lives
// on feat/protocol. During integration merge, this file will be replaced
// by the Protocol agent's full implementation.

// Protocol types are defined as stubs matching feat/protocol interfaces.
// Not all variants/fields are used by the Runtime agent directly — they
// will be exercised once all agents' branches are merged.
#[allow(dead_code)]
pub mod bind;
#[allow(dead_code)]
pub mod codec;
#[allow(dead_code)]
pub mod password;
#[allow(dead_code)]
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
/// dispatches them to the appropriate operation handler.
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
    pub async fn process_message(
        &self,
        session: &mut LdapSession,
        msg: LdapMessage,
    ) -> Vec<LdapMessage> {
        let message_id = msg.message_id;
        session.increment_counter();

        match session.state() {
            session::SessionState::Closed => {
                tracing::warn!(peer = %session.peer_addr(), "message on closed session, ignoring");
                return Vec::new();
            }
            session::SessionState::Connected => {
                match msg.protocol_op {
                    ProtocolOp::BindRequest(ref _req) => {
                        // Fall through to dispatch below.
                    }
                    ProtocolOp::UnbindRequest => {
                        session.transition_to_closed();
                        return Vec::new();
                    }
                    _ => {
                        // NIST AC-3: Reject everything before authentication.
                        return vec![make_error_response(
                            message_id,
                            ResultCode::OperationsError,
                            "bind required before this operation",
                        )];
                    }
                }
            }
            session::SessionState::Bound(_) => {
                // All supported operations are allowed.
            }
        }

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
            _ => {
                tracing::warn!(peer = %session.peer_addr(), "unsupported protocol operation");
                vec![make_error_response(
                    message_id,
                    ResultCode::UnwillingToPerform,
                    "this server does not support the requested operation",
                )]
            }
        }
    }
}

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
