// SPDX-License-Identifier: TBD
//
// Password Modify Extended Operation Handler (RFC 3062)
//
// This is the Runtime agent's copy of the password module from feat/protocol.
// It provides the PasswordStore and BrokerAuthorizer traits that the auth
// module implements.
//
// NIST SP 800-53 Rev. 5:
// - IA-5(1): Passwords set through this operation are ephemeral, hashed, and
//   stored in the site-local runtime schema.
// - AC-3: Only authenticated broker identities may invoke this operation.

use std::future::Future;
use std::pin::Pin;

use super::codec::{
    CodecError, ExtendedRequest, ExtendedResponse, LdapResult, ResultCode,
};
use super::session::LdapSession;

pub const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";

// ---------------------------------------------------------------------------
// PasswordStore trait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum PasswordModifyResult {
    Success,
    UserNotFound,
    InternalError(String),
}

pub trait PasswordStore: Send + Sync {
    fn set_password<'a>(
        &'a self,
        user_dn: &'a str,
        new_password: &'a [u8],
        broker_dn: &'a str,
    ) -> Pin<Box<dyn Future<Output = PasswordModifyResult> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// BrokerAuthorizer trait
// ---------------------------------------------------------------------------

pub trait BrokerAuthorizer: Send + Sync {
    fn is_authorized_broker(&self, dn: &str) -> bool;
}

// ---------------------------------------------------------------------------
// Password Modify handler
// ---------------------------------------------------------------------------

pub struct PasswordModifyHandler<S: PasswordStore, Z: BrokerAuthorizer> {
    store: S,
    authorizer: Z,
}

impl<S: PasswordStore, Z: BrokerAuthorizer> PasswordModifyHandler<S, Z> {
    pub fn new(store: S, authorizer: Z) -> Self {
        Self { store, authorizer }
    }

    pub async fn handle_password_modify(
        &self,
        req: &ExtendedRequest,
        session: &LdapSession,
    ) -> ExtendedResponse {
        if req.request_name != PASSWORD_MODIFY_OID {
            return ExtendedResponse {
                result: LdapResult {
                    result_code: ResultCode::ProtocolError,
                    matched_dn: String::new(),
                    diagnostic_message: format!(
                        "expected OID {}, got {}",
                        PASSWORD_MODIFY_OID, req.request_name
                    ),
                },
                response_name: None,
                response_value: None,
            };
        }

        let bind_info = match session.bind_info() {
            Some(info) => info,
            None => {
                return ExtendedResponse {
                    result: LdapResult {
                        result_code: ResultCode::OperationsError,
                        matched_dn: String::new(),
                        diagnostic_message: "bind required".into(),
                    },
                    response_name: None,
                    response_value: None,
                };
            }
        };

        if !self.authorizer.is_authorized_broker(&bind_info.dn) {
            tracing::warn!(
                peer = %session.peer_addr(),
                dn = %bind_info.dn,
                "password modify rejected: not a broker"
            );
            return ExtendedResponse {
                result: LdapResult {
                    result_code: ResultCode::InsufficientAccessRights,
                    matched_dn: String::new(),
                    diagnostic_message: "only authorized brokers may modify passwords".into(),
                },
                response_name: None,
                response_value: None,
            };
        }

        let request_value = match &req.request_value {
            Some(v) => v,
            None => {
                return ExtendedResponse {
                    result: LdapResult {
                        result_code: ResultCode::ProtocolError,
                        matched_dn: String::new(),
                        diagnostic_message: "missing PasswdModifyRequestValue".into(),
                    },
                    response_name: None,
                    response_value: None,
                };
            }
        };

        // Minimal parsing: extract userIdentity [0] and newPasswd [2].
        let parsed = match parse_passwd_modify_request(request_value) {
            Ok(p) => p,
            Err(e) => {
                return ExtendedResponse {
                    result: LdapResult {
                        result_code: ResultCode::ProtocolError,
                        matched_dn: String::new(),
                        diagnostic_message: format!("malformed request: {e}"),
                    },
                    response_name: None,
                    response_value: None,
                };
            }
        };

        let target_dn = match &parsed.user_identity {
            Some(dn) if !dn.is_empty() => dn.as_str(),
            _ => {
                return ExtendedResponse {
                    result: LdapResult {
                        result_code: ResultCode::UnwillingToPerform,
                        matched_dn: String::new(),
                        diagnostic_message: "userIdentity is required".into(),
                    },
                    response_name: None,
                    response_value: None,
                };
            }
        };

        let new_password = match &parsed.new_passwd {
            Some(pw) if !pw.is_empty() => pw.as_slice(),
            _ => {
                return ExtendedResponse {
                    result: LdapResult {
                        result_code: ResultCode::UnwillingToPerform,
                        matched_dn: String::new(),
                        diagnostic_message: "newPasswd is required".into(),
                    },
                    response_name: None,
                    response_value: None,
                };
            }
        };

        let result = self
            .store
            .set_password(target_dn, new_password, &bind_info.dn)
            .await;

        match result {
            PasswordModifyResult::Success => {
                tracing::info!(
                    peer = %session.peer_addr(),
                    broker = %bind_info.dn,
                    target = %target_dn,
                    "password modified successfully"
                );
                ExtendedResponse {
                    result: LdapResult {
                        result_code: ResultCode::Success,
                        matched_dn: String::new(),
                        diagnostic_message: String::new(),
                    },
                    response_name: None,
                    response_value: None,
                }
            }
            PasswordModifyResult::UserNotFound => ExtendedResponse {
                result: LdapResult {
                    result_code: ResultCode::NoSuchObject,
                    matched_dn: String::new(),
                    diagnostic_message: "target user not found".into(),
                },
                response_name: None,
                response_value: None,
            },
            PasswordModifyResult::InternalError(detail) => {
                tracing::error!(error = %detail, "password modify: internal error");
                ExtendedResponse {
                    result: LdapResult {
                        result_code: ResultCode::Other,
                        matched_dn: String::new(),
                        diagnostic_message: "internal server error".into(),
                    },
                    response_name: None,
                    response_value: None,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PasswdModifyRequestValue parsing
// ---------------------------------------------------------------------------

struct PasswdModifyRequest {
    user_identity: Option<String>,
    #[allow(dead_code)]
    old_passwd: Option<Vec<u8>>,
    new_passwd: Option<Vec<u8>>,
}

fn parse_passwd_modify_request(value: &[u8]) -> Result<PasswdModifyRequest, CodecError> {
    use super::codec::{decode_length, decode_tag, decode_tlv};

    let (tag, seq_contents, _) = decode_tlv(value)?;
    if tag != 0x30 {
        return Err(CodecError::InvalidFormat(format!(
            "PasswdModifyRequestValue must be SEQUENCE, got 0x{tag:02x}"
        )));
    }

    let mut user_identity = None;
    let mut old_passwd = None;
    let mut new_passwd = None;

    let mut offset = 0;
    while offset < seq_contents.len() {
        let (field_tag, field_tag_len) = decode_tag(&seq_contents[offset..])?;
        let (field_len, field_len_len) = decode_length(&seq_contents[offset + field_tag_len..])?;
        let header_len = field_tag_len + field_len_len;
        let field_value = &seq_contents[offset + header_len..offset + header_len + field_len];

        match field_tag {
            0x80 => {
                user_identity = Some(
                    String::from_utf8(field_value.to_vec())
                        .map_err(|_| CodecError::InvalidUtf8)?,
                );
            }
            0x81 => { old_passwd = Some(field_value.to_vec()); }
            0x82 => { new_passwd = Some(field_value.to_vec()); }
            _ => {}
        }

        offset += header_len + field_len;
    }

    Ok(PasswdModifyRequest { user_identity, old_passwd, new_passwd })
}

// ---------------------------------------------------------------------------
// Placeholder implementations
// ---------------------------------------------------------------------------

pub struct PlaceholderPasswordStore;

impl PasswordStore for PlaceholderPasswordStore {
    fn set_password<'a>(
        &'a self,
        _user_dn: &'a str,
        _new_password: &'a [u8],
        _broker_dn: &'a str,
    ) -> Pin<Box<dyn Future<Output = PasswordModifyResult> + Send + 'a>> {
        Box::pin(async { PasswordModifyResult::Success })
    }
}

pub struct StaticBrokerAuthorizer {
    pub authorized_dns: Vec<String>,
}

impl BrokerAuthorizer for StaticBrokerAuthorizer {
    fn is_authorized_broker(&self, dn: &str) -> bool {
        self.authorized_dns.iter().any(|d| d == dn)
    }
}
