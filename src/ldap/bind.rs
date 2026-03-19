// SPDX-License-Identifier: TBD
//
// Bind Operation Handler
//
// This is the Runtime agent's copy of the bind module from feat/protocol.
// It provides the Authenticator trait that DatabaseAuthenticator implements.
//
// NIST SP 800-53 Rev. 5:
// - IA-2 (Identification and Authentication): Users must present a valid DN
//   and password for every session.
// - IA-5 (Authenticator Management): Password material is handled as opaque
//   bytes, never logged, and zeroized after use by the auth module.
// - AC-7 (Unsuccessful Logon Attempts): Bind outcomes are logged for rate-
//   limiting and lockout policies.

use std::future::Future;
use std::pin::Pin;

use super::codec::{
    AuthChoice, BindRequest, BindResponse, LdapResult, ResultCode,
};
use super::session::LdapSession;

// ---------------------------------------------------------------------------
// Authenticator trait
// ---------------------------------------------------------------------------

/// Outcome of a credential verification attempt.
#[derive(Debug, Clone)]
pub enum AuthResult {
    Success,
    InvalidCredentials,
    /// NIST AC-7: Account locked due to excessive failed attempts.
    AccountLocked,
    InternalError(String),
}

/// Trait for pluggable credential verification.
///
/// The DatabaseAuthenticator (in auth/mod.rs) provides the production
/// implementation backed by PostgreSQL.
pub trait Authenticator: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        dn: &'a str,
        password: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Bind handler
// ---------------------------------------------------------------------------

/// Handles LDAPv3 Bind requests.
pub struct BindHandler<A: Authenticator> {
    authenticator: A,
}

impl<A: Authenticator> BindHandler<A> {
    pub fn new(authenticator: A) -> Self {
        Self { authenticator }
    }

    /// Process a BindRequest and return a BindResponse.
    pub async fn handle_bind(
        &self,
        req: &BindRequest,
        session: &mut LdapSession,
    ) -> BindResponse {
        // Reject non-LDAPv3.
        if req.version != 3 {
            tracing::warn!(
                peer = %session.peer_addr(),
                version = req.version,
                "bind rejected: unsupported LDAP version"
            );
            return BindResponse {
                result: LdapResult {
                    result_code: ResultCode::ProtocolError,
                    matched_dn: String::new(),
                    diagnostic_message: "only LDAPv3 (version 3) is supported".into(),
                },
            };
        }

        // Reject SASL.
        let password = match &req.authentication {
            AuthChoice::Simple(pw) => pw,
            AuthChoice::Sasl => {
                tracing::warn!(peer = %session.peer_addr(), "bind rejected: SASL not supported");
                return BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::AuthMethodNotSupported,
                        matched_dn: String::new(),
                        diagnostic_message: "SASL authentication is not supported; use simple bind".into(),
                    },
                };
            }
        };

        // NIST IA-2: Reject anonymous binds.
        if req.name.is_empty() || password.is_empty() {
            tracing::warn!(peer = %session.peer_addr(), dn = %req.name, "bind rejected: anonymous");
            return BindResponse {
                result: LdapResult {
                    result_code: ResultCode::InvalidCredentials,
                    matched_dn: String::new(),
                    diagnostic_message: "anonymous bind is not permitted".into(),
                },
            };
        }

        // Delegate to authenticator.
        let auth_result = self.authenticator.authenticate(&req.name, password).await;

        match auth_result {
            AuthResult::Success => {
                tracing::info!(peer = %session.peer_addr(), dn = %req.name, "bind successful");
                session.transition_to_bound(req.name.clone());
                BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::Success,
                        matched_dn: String::new(),
                        diagnostic_message: String::new(),
                    },
                }
            }
            AuthResult::InvalidCredentials => {
                tracing::warn!(peer = %session.peer_addr(), dn = %req.name, "bind failed: invalid credentials");
                BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::InvalidCredentials,
                        matched_dn: String::new(),
                        diagnostic_message: "invalid credentials".into(),
                    },
                }
            }
            AuthResult::AccountLocked => {
                tracing::warn!(peer = %session.peer_addr(), dn = %req.name, "bind failed: account locked");
                BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::InvalidCredentials,
                        matched_dn: String::new(),
                        diagnostic_message: "invalid credentials".into(),
                    },
                }
            }
            AuthResult::InternalError(detail) => {
                tracing::error!(peer = %session.peer_addr(), dn = %req.name, error = %detail, "bind failed: internal error");
                BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::Other,
                        matched_dn: String::new(),
                        diagnostic_message: "internal server error".into(),
                    },
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Placeholder authenticator for testing
// ---------------------------------------------------------------------------

pub struct PlaceholderAuthenticator;

impl Authenticator for PlaceholderAuthenticator {
    fn authenticate<'a>(
        &'a self,
        _dn: &'a str,
        _password: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + 'a>> {
        Box::pin(async { AuthResult::Success })
    }
}
