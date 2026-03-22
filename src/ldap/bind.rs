// SPDX-License-Identifier: Apache-2.0
//
// Bind Operation Handler
//
// Implements the server-side logic for LDAPv3 Simple Bind (RFC 4511 Section 4.2).
// This module enforces protocol-level validation and delegates credential
// verification to a pluggable authenticator trait.
//
// NIST SP 800-53 Rev. 5:
// - IA-2 (Identification and Authentication): Users must present a valid DN and
//   password for every session. Anonymous and unauthenticated access is rejected.
// - IA-5 (Authenticator Management): Password material is handled as opaque bytes,
//   never logged, and should be zeroized after use by the auth module. The bind
//   handler itself does not store passwords — it passes them through to the
//   authenticator and discards the reference immediately.
// - AC-7 (Unsuccessful Logon Attempts): The bind handler emits structured events
//   for every bind attempt (success or failure) so that rate-limiting and lockout
//   policies can be enforced by the auth/rate_limit module.

use std::future::Future;
use std::pin::Pin;

use super::codec::{AuthChoice, BindRequest, BindResponse, LdapResult, ResultCode};
use super::session::LdapSession;

// ---------------------------------------------------------------------------
// Authenticator trait
// ---------------------------------------------------------------------------

/// Outcome of a credential verification attempt.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Credentials are valid. The caller should transition the session to Bound.
    Success,
    /// The supplied credentials are invalid.
    InvalidCredentials,
    /// The account is locked or rate-limited.
    /// NIST AC-7: Unsuccessful logon attempt threshold exceeded.
    AccountLocked,
    /// An internal error prevented credential verification.
    InternalError(String),
}

/// Trait for pluggable credential verification.
///
/// The Runtime agent will provide a concrete implementation backed by the
/// PostgreSQL runtime schema (ephemeral password hashes). The Protocol agent
/// defines only the interface.
pub trait Authenticator: Send + Sync {
    /// Verify the given DN and password.
    ///
    /// # Arguments
    /// - `dn`: The distinguished name presented in the BindRequest.
    /// - `password`: The raw password bytes from simple authentication.
    ///
    /// # NIST IA-5: Authenticator Management
    /// Implementations MUST NOT log or persist the raw password. The password
    /// bytes should be compared against a stored hash and then dropped.
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
///
/// The handler validates protocol-level constraints (version, auth method,
/// non-anonymous) and delegates credential verification to the configured
/// `Authenticator`.
pub struct BindHandler<A: Authenticator> {
    authenticator: A,
}

impl<A: Authenticator> BindHandler<A> {
    /// Create a new bind handler with the given authenticator.
    pub fn new(authenticator: A) -> Self {
        Self { authenticator }
    }

    /// Process a BindRequest and return a BindResponse.
    ///
    /// This method enforces:
    /// 1. LDAPv3 only (version == 3).
    /// 2. Simple authentication only (no SASL).
    /// 3. Non-anonymous binds (DN and password must be non-empty).
    /// 4. Credential verification via the authenticator.
    ///
    /// # NIST IA-2: Identification and Authentication
    /// Every bind attempt is validated. On failure, the session state is NOT
    /// changed (it remains Connected or retains its previous Bound identity).
    ///
    /// # NIST AC-7: Unsuccessful Logon Attempts
    /// All outcomes are logged with the peer address and DN for audit and
    /// rate-limiting purposes.
    pub async fn handle_bind(&self, req: &BindRequest, session: &mut LdapSession) -> BindResponse {
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

        // Reject SASL — only simple bind is supported.
        let password = match &req.authentication {
            AuthChoice::Simple(pw) => pw,
            AuthChoice::Sasl => {
                tracing::warn!(
                    peer = %session.peer_addr(),
                    "bind rejected: SASL not supported"
                );
                return BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::AuthMethodNotSupported,
                        matched_dn: String::new(),
                        diagnostic_message: "SASL authentication is not supported; use simple bind"
                            .into(),
                    },
                };
            }
        };

        // NIST IA-2: Reject anonymous binds (empty DN or empty password).
        if req.name.is_empty() || password.is_empty() {
            tracing::warn!(
                peer = %session.peer_addr(),
                dn = %req.name,
                "bind rejected: anonymous bind attempt"
            );
            return BindResponse {
                result: LdapResult {
                    result_code: ResultCode::InvalidCredentials,
                    matched_dn: String::new(),
                    diagnostic_message: "anonymous bind is not permitted".into(),
                },
            };
        }

        // Delegate to the authenticator.
        // NIST IA-5: Password bytes are passed by reference and not retained.
        let auth_result = self.authenticator.authenticate(&req.name, password).await;

        match auth_result {
            AuthResult::Success => {
                // NIST IA-2: Successful identification and authentication.
                tracing::info!(
                    peer = %session.peer_addr(),
                    dn = %req.name,
                    "bind successful"
                );
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
                // NIST AC-7: Log failed attempt for rate-limiting.
                tracing::warn!(
                    peer = %session.peer_addr(),
                    dn = %req.name,
                    "bind failed: invalid credentials"
                );
                BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::InvalidCredentials,
                        matched_dn: String::new(),
                        diagnostic_message: "invalid credentials".into(),
                    },
                }
            }
            AuthResult::AccountLocked => {
                // NIST AC-7: Account locked due to excessive failed attempts.
                tracing::warn!(
                    peer = %session.peer_addr(),
                    dn = %req.name,
                    "bind failed: account locked"
                );
                BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::InvalidCredentials,
                        matched_dn: String::new(),
                        // Intentionally vague to avoid information leakage.
                        diagnostic_message: "invalid credentials".into(),
                    },
                }
            }
            AuthResult::InternalError(detail) => {
                tracing::error!(
                    peer = %session.peer_addr(),
                    dn = %req.name,
                    error = %detail,
                    "bind failed: internal error"
                );
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
// Placeholder authenticator for testing / development
// ---------------------------------------------------------------------------

/// A no-op authenticator that always returns success.
///
/// This exists so that the protocol module can compile and be tested in
/// isolation. The Runtime agent will replace this with the real implementation
/// backed by the PostgreSQL runtime schema.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    /// Authenticator that always rejects.
    struct RejectAuthenticator;

    impl Authenticator for RejectAuthenticator {
        fn authenticate<'a>(
            &'a self,
            _dn: &'a str,
            _password: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + 'a>> {
            Box::pin(async { AuthResult::InvalidCredentials })
        }
    }

    #[tokio::test]
    async fn test_successful_bind() {
        let handler = BindHandler::new(PlaceholderAuthenticator);
        let mut session = LdapSession::new(test_addr());
        let req = BindRequest {
            version: 3,
            name: "cn=admin,dc=example,dc=com".into(),
            authentication: AuthChoice::Simple(b"secret".to_vec()),
        };
        let resp = handler.handle_bind(&req, &mut session).await;
        assert_eq!(resp.result.result_code, ResultCode::Success);
        assert!(session.is_bound());
    }

    #[tokio::test]
    async fn test_anonymous_bind_rejected() {
        let handler = BindHandler::new(PlaceholderAuthenticator);
        let mut session = LdapSession::new(test_addr());
        let req = BindRequest {
            version: 3,
            name: String::new(),
            authentication: AuthChoice::Simple(b"secret".to_vec()),
        };
        let resp = handler.handle_bind(&req, &mut session).await;
        assert_eq!(resp.result.result_code, ResultCode::InvalidCredentials);
        assert!(!session.is_bound());
    }

    #[tokio::test]
    async fn test_empty_password_rejected() {
        let handler = BindHandler::new(PlaceholderAuthenticator);
        let mut session = LdapSession::new(test_addr());
        let req = BindRequest {
            version: 3,
            name: "cn=admin".into(),
            authentication: AuthChoice::Simple(Vec::new()),
        };
        let resp = handler.handle_bind(&req, &mut session).await;
        assert_eq!(resp.result.result_code, ResultCode::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_version2_rejected() {
        let handler = BindHandler::new(PlaceholderAuthenticator);
        let mut session = LdapSession::new(test_addr());
        let req = BindRequest {
            version: 2,
            name: "cn=admin".into(),
            authentication: AuthChoice::Simple(b"secret".to_vec()),
        };
        let resp = handler.handle_bind(&req, &mut session).await;
        assert_eq!(resp.result.result_code, ResultCode::ProtocolError);
    }

    #[tokio::test]
    async fn test_sasl_rejected() {
        let handler = BindHandler::new(PlaceholderAuthenticator);
        let mut session = LdapSession::new(test_addr());
        let req = BindRequest {
            version: 3,
            name: "cn=admin".into(),
            authentication: AuthChoice::Sasl,
        };
        let resp = handler.handle_bind(&req, &mut session).await;
        assert_eq!(resp.result.result_code, ResultCode::AuthMethodNotSupported);
    }

    #[tokio::test]
    async fn test_failed_auth() {
        let handler = BindHandler::new(RejectAuthenticator);
        let mut session = LdapSession::new(test_addr());
        let req = BindRequest {
            version: 3,
            name: "cn=admin".into(),
            authentication: AuthChoice::Simple(b"wrong".to_vec()),
        };
        let resp = handler.handle_bind(&req, &mut session).await;
        assert_eq!(resp.result.result_code, ResultCode::InvalidCredentials);
        assert!(!session.is_bound());
    }
}
