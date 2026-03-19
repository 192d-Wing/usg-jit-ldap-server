// SPDX-License-Identifier: TBD
//
// LDAPv3 BER Codec — Manual tag-length-value encoding/decoding.
//
// This is the Runtime agent's copy of the codec module. The canonical
// implementation lives on feat/protocol. During integration merge, this
// file will be replaced by the Protocol agent's full implementation.
//
// The Runtime agent needs these type definitions to compile its wiring
// code (auth, search backend, connection handler). The encode/decode
// functions here are minimal stubs sufficient for type-checking.
//
// NIST SP 800-53 Rev. 5:
// - SC-8: Data transmitted via this codec is always wrapped in TLS at the transport layer.
// - AU-3: Codec errors produce structured diagnostics for audit logging.

use std::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum CodecError {
    Truncated,
    InvalidFormat(String),
    IntegerOverflow,
    InvalidUtf8,
    UnsupportedOperation(u8),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Truncated => write!(f, "BER decode: truncated input"),
            CodecError::InvalidFormat(msg) => write!(f, "BER decode: invalid format: {msg}"),
            CodecError::IntegerOverflow => write!(f, "BER decode: integer overflow"),
            CodecError::InvalidUtf8 => write!(f, "BER decode: invalid UTF-8"),
            CodecError::UnsupportedOperation(tag) => {
                write!(f, "BER decode: unsupported operation tag 0x{tag:02x}")
            }
        }
    }
}

impl std::error::Error for CodecError {}

pub type Result<T> = std::result::Result<T, CodecError>;

// ---------------------------------------------------------------------------
// Result codes (RFC 4511 Section 4.1.9)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum ResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    NoSuchObject = 32,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    Other = 80,
}

impl ResultCode {
    pub fn from_i64(v: i64) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::OperationsError,
            2 => Self::ProtocolError,
            3 => Self::TimeLimitExceeded,
            4 => Self::SizeLimitExceeded,
            7 => Self::AuthMethodNotSupported,
            8 => Self::StrongerAuthRequired,
            32 => Self::NoSuchObject,
            49 => Self::InvalidCredentials,
            50 => Self::InsufficientAccessRights,
            51 => Self::Busy,
            52 => Self::Unavailable,
            53 => Self::UnwillingToPerform,
            _ => Self::Other,
        }
    }
}

// ---------------------------------------------------------------------------
// BER tag constants
// ---------------------------------------------------------------------------

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_ENUMERATED: u8 = 0x0A;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

const TAG_BIND_REQUEST: u8 = 0x60;
const TAG_BIND_RESPONSE: u8 = 0x61;
const TAG_UNBIND_REQUEST: u8 = 0x42;
const TAG_SEARCH_REQUEST: u8 = 0x63;
const TAG_SEARCH_RESULT_ENTRY: u8 = 0x64;
const TAG_SEARCH_RESULT_DONE: u8 = 0x65;
const TAG_EXTENDED_REQUEST: u8 = 0x77;
const TAG_EXTENDED_RESPONSE: u8 = 0x78;

const TAG_CTX_0: u8 = 0x80;
const TAG_CTX_0_CONSTRUCTED: u8 = 0xA0;
const TAG_CTX_1_CONSTRUCTED: u8 = 0xA1;
const TAG_CTX_2_CONSTRUCTED: u8 = 0xA2;
const TAG_CTX_3_CONSTRUCTED: u8 = 0xA3;
const TAG_CTX_4_CONSTRUCTED: u8 = 0xA4;
const TAG_CTX_7: u8 = 0x87;

// ---------------------------------------------------------------------------
// Core LDAP types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LdapMessage {
    pub message_id: i32,
    pub protocol_op: ProtocolOp,
}

#[derive(Debug, Clone)]
pub enum ProtocolOp {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest,
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(LdapResult),
    ExtendedRequest(ExtendedRequest),
    ExtendedResponse(ExtendedResponse),
}

#[derive(Debug, Clone)]
pub struct BindRequest {
    pub version: i32,
    pub name: String,
    pub authentication: AuthChoice,
}

#[derive(Debug, Clone)]
pub enum AuthChoice {
    Simple(Vec<u8>),
    Sasl,
}

#[derive(Debug, Clone)]
pub struct BindResponse {
    pub result: LdapResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

impl SearchScope {
    pub fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(Self::BaseObject),
            1 => Ok(Self::SingleLevel),
            2 => Ok(Self::WholeSubtree),
            _ => Err(CodecError::InvalidFormat(format!("invalid search scope: {v}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerefAliases {
    NeverDerefAliases = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}

#[derive(Debug, Clone)]
pub struct SearchRequest {
    pub base_object: String,
    pub scope: SearchScope,
    pub deref_aliases: DerefAliases,
    pub size_limit: i32,
    pub time_limit: i32,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    pub object_name: String,
    pub attributes: Vec<PartialAttribute>,
}

#[derive(Debug, Clone)]
pub struct PartialAttribute {
    pub attr_type: String,
    pub values: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct LdapResult {
    pub result_code: ResultCode,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone)]
pub struct ExtendedRequest {
    pub request_name: String,
    pub request_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub response_name: Option<String>,
    pub response_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    EqualityMatch(AttributeValueAssertion),
    Substrings(SubstringFilter),
    Present(String),
    ApproxMatch(AttributeValueAssertion),
}

#[derive(Debug, Clone)]
pub struct AttributeValueAssertion {
    pub attribute_desc: String,
    pub assertion_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SubstringFilter {
    pub attr_type: String,
    pub initial: Option<Vec<u8>>,
    pub any: Vec<Vec<u8>>,
    pub r#final: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// BER encoding helpers
// ---------------------------------------------------------------------------

pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len <= 0xFF_FFFF {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

pub fn encode_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

pub fn encode_sequence(contents: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_SEQUENCE, contents)
}

pub fn encode_integer(val: i64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0 && b != 0xFF).unwrap_or(7);
    let start = if val >= 0 && bytes[start] & 0x80 != 0 { start.saturating_sub(1) } else if val < 0 && bytes[start] & 0x80 == 0 { start.saturating_sub(1) } else { start };
    encode_tlv(TAG_INTEGER, &bytes[start..])
}

pub fn encode_octet_string(val: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, val)
}

pub fn encode_enumerated(val: i64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0 && b != 0xFF).unwrap_or(7);
    encode_tlv(TAG_ENUMERATED, &bytes[start..])
}

// ---------------------------------------------------------------------------
// BER decoding helpers
// ---------------------------------------------------------------------------

pub fn decode_tag(bytes: &[u8]) -> Result<(u8, usize)> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    Ok((bytes[0], 1))
}

pub fn decode_length(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    if bytes[0] < 0x80 {
        Ok((bytes[0] as usize, 1))
    } else {
        let num_bytes = (bytes[0] & 0x7F) as usize;
        if bytes.len() < 1 + num_bytes {
            return Err(CodecError::Truncated);
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | bytes[1 + i] as usize;
        }
        Ok((len, 1 + num_bytes))
    }
}

pub fn decode_tlv(bytes: &[u8]) -> Result<(u8, &[u8], usize)> {
    let (tag, tag_len) = decode_tag(bytes)?;
    let (content_len, len_len) = decode_length(&bytes[tag_len..])?;
    let header_len = tag_len + len_len;
    let total_len = header_len + content_len;
    if bytes.len() < total_len {
        return Err(CodecError::Truncated);
    }
    Ok((tag, &bytes[header_len..total_len], total_len))
}

pub fn decode_integer_value(bytes: &[u8]) -> Result<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(CodecError::IntegerOverflow);
    }
    let mut val: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        val = (val << 8) | b as i64;
    }
    Ok(val)
}

// ---------------------------------------------------------------------------
// Message-level encode/decode
// ---------------------------------------------------------------------------

pub fn decode_ldap_message(bytes: &[u8]) -> Result<(LdapMessage, usize)> {
    let (tag, seq_contents, total_len) = decode_tlv(bytes)?;
    if tag != TAG_SEQUENCE {
        return Err(CodecError::InvalidFormat("expected SEQUENCE".into()));
    }

    // Message ID (INTEGER)
    let (id_tag, id_val, id_total) = decode_tlv(seq_contents)?;
    if id_tag != TAG_INTEGER {
        return Err(CodecError::InvalidFormat("expected INTEGER for message ID".into()));
    }
    let message_id = decode_integer_value(id_val)? as i32;

    // Protocol operation
    let remaining = &seq_contents[id_total..];
    let (op_tag, op_val, _) = decode_tlv(remaining)?;
    let protocol_op = decode_protocol_op(op_tag, op_val)?;

    Ok((LdapMessage { message_id, protocol_op }, total_len))
}

fn decode_protocol_op(tag: u8, value: &[u8]) -> Result<ProtocolOp> {
    match tag {
        TAG_BIND_REQUEST => Ok(ProtocolOp::BindRequest(decode_bind_request(value)?)),
        TAG_UNBIND_REQUEST => Ok(ProtocolOp::UnbindRequest),
        TAG_SEARCH_REQUEST => Ok(ProtocolOp::SearchRequest(decode_search_request(value)?)),
        TAG_EXTENDED_REQUEST => Ok(ProtocolOp::ExtendedRequest(decode_extended_request(value)?)),
        _ => Err(CodecError::UnsupportedOperation(tag)),
    }
}

fn decode_bind_request(value: &[u8]) -> Result<BindRequest> {
    // version (INTEGER)
    let (_, ver_bytes, ver_total) = decode_tlv(value)?;
    let version = decode_integer_value(ver_bytes)? as i32;

    // name (OCTET STRING)
    let remaining = &value[ver_total..];
    let (_, name_bytes, name_total) = decode_tlv(remaining)?;
    let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;

    // authentication choice
    let remaining = &remaining[name_total..];
    let (auth_tag, auth_bytes, _) = decode_tlv(remaining)?;
    let authentication = match auth_tag {
        TAG_CTX_0 => AuthChoice::Simple(auth_bytes.to_vec()),
        TAG_CTX_0_CONSTRUCTED => AuthChoice::Sasl,
        _ => AuthChoice::Simple(auth_bytes.to_vec()),
    };

    Ok(BindRequest { version, name, authentication })
}

fn decode_search_request(value: &[u8]) -> Result<SearchRequest> {
    // Minimal stub: parse enough for the connection handler to work.
    let (_, base_bytes, base_total) = decode_tlv(value)?;
    let base_object = String::from_utf8(base_bytes.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;

    let remaining = &value[base_total..];
    let (_, scope_bytes, scope_total) = decode_tlv(remaining)?;
    let scope = SearchScope::from_i64(decode_integer_value(scope_bytes)?)?;

    let remaining = &remaining[scope_total..];
    let (_, deref_bytes, deref_total) = decode_tlv(remaining)?;
    let _deref = decode_integer_value(deref_bytes)?;

    let remaining = &remaining[deref_total..];
    let (_, size_bytes, size_total) = decode_tlv(remaining)?;
    let size_limit = decode_integer_value(size_bytes)? as i32;

    let remaining = &remaining[size_total..];
    let (_, time_bytes, time_total) = decode_tlv(remaining)?;
    let time_limit = decode_integer_value(time_bytes)? as i32;

    let remaining = &remaining[time_total..];
    let (_, types_bytes, types_total) = decode_tlv(remaining)?;
    let types_only = !types_bytes.is_empty() && types_bytes[0] != 0;

    // Filter and attributes: simplified parsing
    let remaining = &remaining[types_total..];
    let (filter_tag, filter_val, filter_total) = decode_tlv(remaining)?;
    let filter = parse_filter_simple(filter_tag, filter_val);

    let remaining = &remaining[filter_total..];
    let mut attributes = Vec::new();
    if !remaining.is_empty() {
        let (_, attrs_content, _) = decode_tlv(remaining)?;
        let mut offset = 0;
        while offset < attrs_content.len() {
            if let Ok((_, attr_bytes, attr_total)) = decode_tlv(&attrs_content[offset..]) {
                if let Ok(s) = String::from_utf8(attr_bytes.to_vec()) {
                    attributes.push(s);
                }
                offset += attr_total;
            } else {
                break;
            }
        }
    }

    Ok(SearchRequest {
        base_object,
        scope,
        deref_aliases: DerefAliases::NeverDerefAliases,
        size_limit,
        time_limit,
        types_only,
        filter,
        attributes,
    })
}

fn parse_filter_simple(tag: u8, value: &[u8]) -> Filter {
    match tag {
        TAG_CTX_7 => {
            // Present filter
            Filter::Present(String::from_utf8_lossy(value).to_string())
        }
        TAG_CTX_3_CONSTRUCTED => {
            // EqualityMatch
            if let Ok(ava) = parse_ava(value) {
                Filter::EqualityMatch(ava)
            } else {
                Filter::Present("objectClass".into())
            }
        }
        TAG_CTX_0_CONSTRUCTED => {
            // AND
            let mut filters = Vec::new();
            let mut offset = 0;
            while offset < value.len() {
                if let Ok((t, v, total)) = decode_tlv(&value[offset..]) {
                    filters.push(parse_filter_simple(t, v));
                    offset += total;
                } else {
                    break;
                }
            }
            Filter::And(filters)
        }
        TAG_CTX_1_CONSTRUCTED => {
            // OR
            let mut filters = Vec::new();
            let mut offset = 0;
            while offset < value.len() {
                if let Ok((t, v, total)) = decode_tlv(&value[offset..]) {
                    filters.push(parse_filter_simple(t, v));
                    offset += total;
                } else {
                    break;
                }
            }
            Filter::Or(filters)
        }
        _ => Filter::Present("objectClass".into()),
    }
}

fn parse_ava(value: &[u8]) -> Result<AttributeValueAssertion> {
    let (_, attr_bytes, attr_total) = decode_tlv(value)?;
    let attribute_desc = String::from_utf8(attr_bytes.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;
    let remaining = &value[attr_total..];
    let (_, val_bytes, _) = decode_tlv(remaining)?;
    Ok(AttributeValueAssertion {
        attribute_desc,
        assertion_value: val_bytes.to_vec(),
    })
}

fn decode_extended_request(value: &[u8]) -> Result<ExtendedRequest> {
    let (_, name_bytes, name_total) = decode_tlv(value)?;
    let request_name = String::from_utf8(name_bytes.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;
    let remaining = &value[name_total..];
    let request_value = if !remaining.is_empty() {
        let (_, val_bytes, _) = decode_tlv(remaining)?;
        Some(val_bytes.to_vec())
    } else {
        None
    };
    Ok(ExtendedRequest { request_name, request_value })
}

pub fn encode_ldap_message(msg: &LdapMessage) -> Result<Vec<u8>> {
    let mut contents = encode_integer(msg.message_id as i64);
    contents.extend_from_slice(&encode_protocol_op(&msg.protocol_op)?);
    Ok(encode_sequence(&contents))
}

fn encode_protocol_op(op: &ProtocolOp) -> Result<Vec<u8>> {
    match op {
        ProtocolOp::BindResponse(resp) => {
            let contents = encode_ldap_result_contents(&resp.result);
            Ok(encode_tlv(TAG_BIND_RESPONSE, &contents))
        }
        ProtocolOp::SearchResultEntry(entry) => encode_search_result_entry(entry),
        ProtocolOp::SearchResultDone(result) => {
            Ok(encode_tlv(TAG_SEARCH_RESULT_DONE, &encode_ldap_result_contents(result)))
        }
        ProtocolOp::ExtendedResponse(resp) => {
            let mut contents = encode_ldap_result_contents(&resp.result);
            if let Some(name) = &resp.response_name {
                contents.extend_from_slice(&encode_tlv(0x8A, name.as_bytes()));
            }
            if let Some(val) = &resp.response_value {
                contents.extend_from_slice(&encode_tlv(0x8B, val));
            }
            Ok(encode_tlv(TAG_EXTENDED_RESPONSE, &contents))
        }
        ProtocolOp::UnbindRequest => Ok(encode_tlv(TAG_UNBIND_REQUEST, &[])),
        _ => Err(CodecError::InvalidFormat("cannot encode client-side operations from server".into())),
    }
}

fn encode_ldap_result_contents(result: &LdapResult) -> Vec<u8> {
    let mut contents = encode_enumerated(result.result_code as i64);
    contents.extend_from_slice(&encode_octet_string(result.matched_dn.as_bytes()));
    contents.extend_from_slice(&encode_octet_string(result.diagnostic_message.as_bytes()));
    contents
}

fn encode_search_result_entry(entry: &SearchResultEntry) -> Result<Vec<u8>> {
    let mut contents = encode_octet_string(entry.object_name.as_bytes());
    let mut attrs_contents = Vec::new();
    for attr in &entry.attributes {
        let mut attr_contents = encode_octet_string(attr.attr_type.as_bytes());
        let mut values_content = Vec::new();
        for val in &attr.values {
            values_content.extend_from_slice(&encode_octet_string(val));
        }
        attr_contents.extend_from_slice(&encode_tlv(TAG_SET, &values_content));
        attrs_contents.extend_from_slice(&encode_sequence(&attr_contents));
    }
    contents.extend_from_slice(&encode_sequence(&attrs_contents));
    Ok(encode_tlv(TAG_SEARCH_RESULT_ENTRY, &contents))
}

// ---------------------------------------------------------------------------
// LdapCodec — frame-level codec
// ---------------------------------------------------------------------------

/// A stateless LDAPv3 message framer.
pub struct LdapCodec;

impl LdapCodec {
    pub fn new() -> Self {
        Self
    }

    /// Attempt to extract a complete LDAPMessage from the front of `buf`.
    pub fn decode_frame(&self, buf: &[u8]) -> Result<Option<(LdapMessage, usize)>> {
        if buf.is_empty() {
            return Ok(None);
        }

        let (tag, tag_len) = match decode_tag(buf) {
            Ok(v) => v,
            Err(CodecError::Truncated) => return Ok(None),
            Err(e) => return Err(e),
        };
        if tag != TAG_SEQUENCE {
            return Err(CodecError::InvalidFormat(format!(
                "expected SEQUENCE tag 0x30, got 0x{tag:02x}"
            )));
        }

        let (content_len, len_len) = match decode_length(&buf[tag_len..]) {
            Ok(v) => v,
            Err(CodecError::Truncated) => return Ok(None),
            Err(e) => return Err(e),
        };

        let total_len = tag_len + len_len + content_len;
        if buf.len() < total_len {
            return Ok(None);
        }

        let (msg, consumed) = decode_ldap_message(buf)?;
        Ok(Some((msg, consumed)))
    }

    /// Encode an LDAPMessage to wire bytes.
    pub fn encode_frame(&self, msg: &LdapMessage) -> Result<Vec<u8>> {
        encode_ldap_message(msg)
    }
}

impl Default for LdapCodec {
    fn default() -> Self {
        Self::new()
    }
}
