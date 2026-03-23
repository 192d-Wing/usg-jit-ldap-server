// SPDX-License-Identifier: Apache-2.0
//
// LDAPv3 BER Codec — Manual tag-length-value encoding/decoding.
//
// This module implements the minimal BER subset required for LDAPv3 message
// framing as defined in RFC 4511. We avoid external ASN.1 crate dependencies
// to keep the codec fully auditable and minimize the trust surface.
//
// NIST SP 800-53 Rev. 5:
// - SC-8: Data transmitted via this codec is always wrapped in TLS at the transport layer.
// - AU-3: Codec errors produce structured diagnostics for audit logging.

use std::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during BER encoding or decoding.
#[derive(Debug, Clone)]
pub enum CodecError {
    /// Not enough bytes available to complete a decode.
    Truncated,
    /// A tag or structure does not match the expected LDAPv3 grammar.
    InvalidFormat(String),
    /// An integer value is out of the representable range.
    IntegerOverflow,
    /// A string field contains invalid UTF-8.
    InvalidUtf8,
    /// The message references an unsupported or unknown operation tag.
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

/// LDAPv3 result codes used by this server.
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
    #[must_use]
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

// Universal class tags
const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_ENUMERATED: u8 = 0x0A;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

// Application class tags for LDAP operations (constructed)
const TAG_BIND_REQUEST: u8 = 0x60; // [APPLICATION 0] CONSTRUCTED
const TAG_BIND_RESPONSE: u8 = 0x61; // [APPLICATION 1] CONSTRUCTED
const TAG_UNBIND_REQUEST: u8 = 0x42; // [APPLICATION 2] PRIMITIVE
const TAG_SEARCH_REQUEST: u8 = 0x63; // [APPLICATION 3] CONSTRUCTED
const TAG_SEARCH_RESULT_ENTRY: u8 = 0x64; // [APPLICATION 4] CONSTRUCTED
const TAG_SEARCH_RESULT_DONE: u8 = 0x65; // [APPLICATION 5] CONSTRUCTED
const TAG_EXTENDED_REQUEST: u8 = 0x77; // [APPLICATION 23] CONSTRUCTED
const TAG_EXTENDED_RESPONSE: u8 = 0x78; // [APPLICATION 24] CONSTRUCTED

// Context-specific tags used within operations
const TAG_CTX_0: u8 = 0x80; // [0] PRIMITIVE (e.g., simple auth in BindRequest)
const TAG_CTX_0_CONSTRUCTED: u8 = 0xA0; // [0] CONSTRUCTED (e.g., AND filter)
const TAG_CTX_1_CONSTRUCTED: u8 = 0xA1; // [1] CONSTRUCTED (e.g., OR filter)
const TAG_CTX_2_CONSTRUCTED: u8 = 0xA2; // [2] CONSTRUCTED (e.g., NOT filter)
const TAG_CTX_3_CONSTRUCTED: u8 = 0xA3; // [3] CONSTRUCTED (e.g., equalityMatch)
const TAG_CTX_4_CONSTRUCTED: u8 = 0xA4; // [4] CONSTRUCTED (e.g., substrings)
const TAG_CTX_7: u8 = 0x87; // [7] PRIMITIVE (e.g., present filter)

// ---------------------------------------------------------------------------
// Security limits — NIST SI-10 (Information Input Validation)
// ---------------------------------------------------------------------------

/// Maximum size of a single LDAP message in bytes (10 MB).
/// Prevents memory exhaustion from oversized BER frames.
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum recursion depth for filter parsing.
/// Prevents stack overflow from deeply nested AND/OR/NOT filters.
pub const MAX_FILTER_DEPTH: usize = 32;

/// Maximum number of child filters in an AND or OR set.
pub const MAX_FILTER_CHILDREN: usize = 256;

/// Maximum number of requested attributes in a SearchRequest.
pub const MAX_ATTRIBUTES: usize = 256;

/// Maximum number of 'any' components in a SubstringFilter.
pub const MAX_SUBSTRING_ANY: usize = 64;

// ---------------------------------------------------------------------------
// Core LDAP types
// ---------------------------------------------------------------------------

/// Top-level LDAPv3 message envelope.
#[derive(Debug, Clone)]
pub struct LdapMessage {
    pub message_id: i32,
    pub protocol_op: ProtocolOp,
}

/// LDAPv3 protocol operations supported by this server.
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

/// Bind request — only simple authentication is supported.
#[derive(Debug, Clone)]
pub struct BindRequest {
    pub version: i32,
    pub name: String,
    pub authentication: AuthChoice,
}

/// Authentication choice — we only support simple (password) bind.
#[derive(Debug, Clone)]
pub enum AuthChoice {
    /// Simple authentication: raw password bytes.
    Simple(Vec<u8>),
    /// SASL — recognized for rejection purposes only.
    Sasl,
}

/// Bind response.
#[derive(Debug, Clone)]
pub struct BindResponse {
    pub result: LdapResult,
    // server_sasl_creds omitted — we never use SASL.
}

/// Search scope (RFC 4511 Section 4.5.1).
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
            _ => Err(CodecError::InvalidFormat(format!(
                "invalid search scope: {v}"
            ))),
        }
    }
}

/// Dereference aliases policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerefAliases {
    NeverDerefAliases = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}

impl DerefAliases {
    pub fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(Self::NeverDerefAliases),
            1 => Ok(Self::DerefInSearching),
            2 => Ok(Self::DerefFindingBaseObj),
            3 => Ok(Self::DerefAlways),
            _ => Err(CodecError::InvalidFormat(format!(
                "invalid deref aliases: {v}"
            ))),
        }
    }
}

/// Search request.
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

/// Search filter (RFC 4511 Section 4.5.1.7).
/// We support the subset needed for typical LDAP client queries.
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

/// Attribute-value assertion used in equality and approx filters.
#[derive(Debug, Clone)]
pub struct AttributeValueAssertion {
    pub attribute_desc: String,
    pub assertion_value: Vec<u8>,
}

/// Substring filter components.
#[derive(Debug, Clone)]
pub struct SubstringFilter {
    pub attribute_desc: String,
    pub initial: Option<Vec<u8>>,
    pub any: Vec<Vec<u8>>,
    pub final_value: Option<Vec<u8>>,
}

/// A partial attribute (name + set of values) returned in search results.
#[derive(Debug, Clone)]
pub struct PartialAttribute {
    pub attr_type: String,
    pub values: Vec<Vec<u8>>,
}

/// A single search result entry.
#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    pub object_name: String,
    pub attributes: Vec<PartialAttribute>,
}

/// LDAPResult structure shared across response types.
#[derive(Debug, Clone)]
pub struct LdapResult {
    pub result_code: ResultCode,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

/// Extended request (RFC 4511 Section 4.12).
#[derive(Debug, Clone)]
pub struct ExtendedRequest {
    pub request_name: String,
    pub request_value: Option<Vec<u8>>,
}

/// Extended response.
#[derive(Debug, Clone)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub response_name: Option<String>,
    pub response_value: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// BER low-level encoding helpers
// ---------------------------------------------------------------------------

/// Encode a BER length field.
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

/// Wrap `contents` in a TLV with the given tag.
pub fn encode_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// Encode a SEQUENCE (tag 0x30) wrapping the given contents.
pub fn encode_sequence(contents: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_SEQUENCE, contents)
}

/// Encode a SET (tag 0x31) wrapping the given contents.
pub fn encode_set(contents: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_SET, contents)
}

/// Encode a BER INTEGER.
pub fn encode_integer(val: i64) -> Vec<u8> {
    let mut bytes = val.to_be_bytes().to_vec();
    // Remove leading redundant bytes (keep minimal two's-complement form).
    while bytes.len() > 1 {
        if (bytes[0] == 0x00 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0)
        {
            bytes.remove(0);
        } else {
            break;
        }
    }
    encode_tlv(TAG_INTEGER, &bytes)
}

/// Encode a BER OCTET STRING.
pub fn encode_octet_string(val: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, val)
}

/// Encode a BER ENUMERATED.
pub fn encode_enumerated(val: i64) -> Vec<u8> {
    let mut bytes = val.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        if (bytes[0] == 0x00 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0)
        {
            bytes.remove(0);
        } else {
            break;
        }
    }
    encode_tlv(TAG_ENUMERATED, &bytes)
}

/// Encode a BER BOOLEAN.
pub fn encode_boolean(val: bool) -> Vec<u8> {
    encode_tlv(TAG_BOOLEAN, &[if val { 0xFF } else { 0x00 }])
}

// ---------------------------------------------------------------------------
// BER low-level decoding helpers
// ---------------------------------------------------------------------------

/// Decode a BER tag byte, returning (tag, bytes_consumed).
/// For our purposes we treat the tag as a single byte; multi-byte tags
/// (tag number >= 31) are not used in LDAPv3.
pub fn decode_tag(bytes: &[u8]) -> Result<(u8, usize)> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    Ok((bytes[0], 1))
}

/// Decode a BER length field, returning (length_value, bytes_consumed).
pub fn decode_length(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    let first = bytes[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_octets = (first & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 {
            return Err(CodecError::InvalidFormat(format!(
                "unsupported length encoding: {num_octets} octets"
            )));
        }
        if bytes.len() < 1 + num_octets {
            return Err(CodecError::Truncated);
        }
        let mut len: usize = 0;
        for i in 0..num_octets {
            len = len
                .checked_shl(8)
                .ok_or_else(|| CodecError::InvalidFormat("BER length overflow".into()))?
                | (bytes[1 + i] as usize);
        }
        Ok((len, 1 + num_octets))
    }
}

/// Decode a complete TLV, returning (tag, value_slice, total_bytes_consumed).
pub fn decode_tlv(bytes: &[u8]) -> Result<(u8, &[u8], usize)> {
    let (tag, tag_len) = decode_tag(bytes)?;
    let (content_len, len_len) = decode_length(&bytes[tag_len..])?;
    let header_len = tag_len + len_len;
    if bytes.len() < header_len + content_len {
        return Err(CodecError::Truncated);
    }
    Ok((
        tag,
        &bytes[header_len..header_len + content_len],
        header_len + content_len,
    ))
}

/// Decode a BER INTEGER from raw value bytes (no tag/length).
pub fn decode_integer_value(bytes: &[u8]) -> Result<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(CodecError::IntegerOverflow);
    }
    let mut val: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        val = (val << 8) | (b as i64);
    }
    Ok(val)
}

/// Decode a BER INTEGER TLV, returning (value, bytes_consumed).
pub fn decode_integer(bytes: &[u8]) -> Result<(i64, usize)> {
    let (tag, value, consumed) = decode_tlv(bytes)?;
    if tag != TAG_INTEGER {
        return Err(CodecError::InvalidFormat(format!(
            "expected INTEGER tag 0x02, got 0x{tag:02x}"
        )));
    }
    Ok((decode_integer_value(value)?, consumed))
}

/// Decode a BER OCTET STRING TLV, returning (value, bytes_consumed).
pub fn decode_octet_string(bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
    let (tag, value, consumed) = decode_tlv(bytes)?;
    if tag != TAG_OCTET_STRING {
        return Err(CodecError::InvalidFormat(format!(
            "expected OCTET STRING tag 0x04, got 0x{tag:02x}"
        )));
    }
    Ok((value.to_vec(), consumed))
}

/// Decode a BER ENUMERATED TLV, returning (value, bytes_consumed).
pub fn decode_enumerated(bytes: &[u8]) -> Result<(i64, usize)> {
    let (tag, value, consumed) = decode_tlv(bytes)?;
    if tag != TAG_ENUMERATED {
        return Err(CodecError::InvalidFormat(format!(
            "expected ENUMERATED tag 0x0A, got 0x{tag:02x}"
        )));
    }
    Ok((decode_integer_value(value)?, consumed))
}

/// Decode a BER BOOLEAN TLV, returning (value, bytes_consumed).
pub fn decode_boolean(bytes: &[u8]) -> Result<(bool, usize)> {
    let (tag, value, consumed) = decode_tlv(bytes)?;
    if tag != TAG_BOOLEAN {
        return Err(CodecError::InvalidFormat(format!(
            "expected BOOLEAN tag 0x01, got 0x{tag:02x}"
        )));
    }
    if value.len() != 1 {
        return Err(CodecError::InvalidFormat(
            "BOOLEAN value must be exactly 1 byte".into(),
        ));
    }
    Ok((value[0] != 0x00, consumed))
}

/// Decode a UTF-8 string from an OCTET STRING TLV.
pub fn decode_ldap_string(bytes: &[u8]) -> Result<(String, usize)> {
    let (raw, consumed) = decode_octet_string(bytes)?;
    // Reject embedded NULL bytes which can cause DN/filter comparison bypasses.
    if raw.contains(&0) {
        return Err(CodecError::InvalidFormat(
            "embedded NULL byte in LDAP string".into(),
        ));
    }
    let s = String::from_utf8(raw).map_err(|_| CodecError::InvalidUtf8)?;
    Ok((s, consumed))
}

// ---------------------------------------------------------------------------
// Sequence iteration helper
// ---------------------------------------------------------------------------

/// Iterate through elements inside a SEQUENCE/SET's value bytes.
struct TlvIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TlvIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    fn next_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let (tag, value, consumed) = decode_tlv(self.remaining())?;
        self.offset = self
            .offset
            .checked_add(consumed)
            .ok_or_else(|| CodecError::InvalidFormat("TLV iterator offset overflow".into()))?;
        Ok((tag, value))
    }
}

// ---------------------------------------------------------------------------
// High-level LDAP message decoding
// ---------------------------------------------------------------------------

/// Decode an LDAPMessage from the wire. Returns the message and bytes consumed.
///
/// Wire format:
/// ```text
/// LDAPMessage ::= SEQUENCE {
///     messageID  INTEGER,
///     protocolOp CHOICE { ... },
///     controls   [0] Controls OPTIONAL   -- ignored
/// }
/// ```
pub fn decode_ldap_message(bytes: &[u8]) -> Result<(LdapMessage, usize)> {
    // Outer SEQUENCE
    let (tag, seq_value, total_consumed) = decode_tlv(bytes)?;
    if tag != TAG_SEQUENCE {
        return Err(CodecError::InvalidFormat(format!(
            "LDAPMessage must be a SEQUENCE, got tag 0x{tag:02x}"
        )));
    }

    let mut iter = TlvIter::new(seq_value);

    // messageID INTEGER (RFC 4511: 0 .. maxInt where maxInt = 2147483647)
    let (msg_id, _) = decode_integer(iter.remaining())?;
    let _ = iter.next_tlv(); // advance past the integer
    if msg_id < 0 || msg_id > i32::MAX as i64 {
        return Err(CodecError::InvalidFormat(format!(
            "messageID {msg_id} out of range [0, 2147483647]"
        )));
    }
    let message_id = msg_id as i32;

    // protocolOp — peek at the tag to determine which operation
    if iter.is_empty() {
        return Err(CodecError::InvalidFormat(
            "LDAPMessage missing protocolOp".into(),
        ));
    }
    let (op_tag, op_value) = iter.next_tlv()?;
    let protocol_op = decode_protocol_op(op_tag, op_value)?;

    // controls [0] — we ignore any controls for v1.

    Ok((
        LdapMessage {
            message_id,
            protocol_op,
        },
        total_consumed,
    ))
}

/// Decode the protocol operation based on its application tag.
fn decode_protocol_op(tag: u8, value: &[u8]) -> Result<ProtocolOp> {
    match tag {
        TAG_BIND_REQUEST => decode_bind_request(value).map(ProtocolOp::BindRequest),
        TAG_UNBIND_REQUEST => Ok(ProtocolOp::UnbindRequest),
        TAG_SEARCH_REQUEST => decode_search_request(value).map(ProtocolOp::SearchRequest),
        TAG_EXTENDED_REQUEST => decode_extended_request(value).map(ProtocolOp::ExtendedRequest),
        _ => Err(CodecError::UnsupportedOperation(tag)),
    }
}

/// Decode a BindRequest from its value bytes.
///
/// ```text
/// BindRequest ::= [APPLICATION 0] SEQUENCE {
///     version        INTEGER,
///     name           LDAPDN (OCTET STRING),
///     authentication AuthenticationChoice
/// }
/// AuthenticationChoice ::= CHOICE {
///     simple [0] OCTET STRING,
///     sasl   [3] SaslCredentials
/// }
/// ```
fn decode_bind_request(value: &[u8]) -> Result<BindRequest> {
    let mut iter = TlvIter::new(value);

    // version INTEGER
    let (version, _) = decode_integer(iter.remaining())?;
    iter.next_tlv()?;

    // name OCTET STRING (LDAPDN)
    let (name, _) = decode_ldap_string(iter.remaining())?;
    iter.next_tlv()?;

    // authentication — context-specific tag
    if iter.is_empty() {
        return Err(CodecError::InvalidFormat(
            "BindRequest missing authentication field".into(),
        ));
    }
    let (auth_tag, auth_value) = iter.next_tlv()?;
    let authentication = match auth_tag {
        TAG_CTX_0 => AuthChoice::Simple(auth_value.to_vec()),
        0xA3 => AuthChoice::Sasl, // [3] CONSTRUCTED — SASL
        _ => {
            return Err(CodecError::InvalidFormat(format!(
                "unknown authentication choice tag 0x{auth_tag:02x}"
            )));
        }
    };

    Ok(BindRequest {
        version: version as i32,
        name,
        authentication,
    })
}

/// Decode a SearchRequest from its value bytes.
///
/// ```text
/// SearchRequest ::= [APPLICATION 3] SEQUENCE {
///     baseObject   LDAPDN,
///     scope        ENUMERATED,
///     derefAliases ENUMERATED,
///     sizeLimit    INTEGER,
///     timeLimit    INTEGER,
///     typesOnly    BOOLEAN,
///     filter       Filter,
///     attributes   AttributeSelection (SEQUENCE OF OCTET STRING)
/// }
/// ```
fn decode_search_request(value: &[u8]) -> Result<SearchRequest> {
    let mut iter = TlvIter::new(value);

    // baseObject OCTET STRING
    let (base_object, _) = decode_ldap_string(iter.remaining())?;
    iter.next_tlv()?;

    // scope ENUMERATED
    let (scope_val, _) = decode_enumerated(iter.remaining())?;
    iter.next_tlv()?;
    let scope = SearchScope::from_i64(scope_val)?;

    // derefAliases ENUMERATED
    let (deref_val, _) = decode_enumerated(iter.remaining())?;
    iter.next_tlv()?;
    let deref_aliases = DerefAliases::from_i64(deref_val)?;

    // sizeLimit INTEGER (RFC 4511: non-negative)
    let (size_limit_raw, _) = decode_integer(iter.remaining())?;
    iter.next_tlv()?;
    let size_limit = if size_limit_raw < 0 {
        0i32
    } else {
        size_limit_raw.min(i32::MAX as i64) as i32
    };

    // timeLimit INTEGER (RFC 4511: non-negative)
    let (time_limit_raw, _) = decode_integer(iter.remaining())?;
    iter.next_tlv()?;
    let time_limit = if time_limit_raw < 0 {
        0i32
    } else {
        time_limit_raw.min(i32::MAX as i64) as i32
    };

    // typesOnly BOOLEAN
    let (types_only, _) = decode_boolean(iter.remaining())?;
    iter.next_tlv()?;

    // filter — complex; decode recursively
    let (filter_tag, filter_value) = iter.next_tlv()?;
    let filter = decode_filter(filter_tag, filter_value, 0)?;

    // attributes SEQUENCE OF LDAPString
    let (attrs_tag, attrs_value) = iter.next_tlv()?;
    if attrs_tag != TAG_SEQUENCE {
        return Err(CodecError::InvalidFormat(format!(
            "expected SEQUENCE for attributes, got 0x{attrs_tag:02x}"
        )));
    }
    let mut attributes = Vec::new();
    let mut attrs_iter = TlvIter::new(attrs_value);
    while !attrs_iter.is_empty() {
        let (attr_tag, attr_val) = attrs_iter.next_tlv()?;
        if attr_tag != TAG_OCTET_STRING {
            return Err(CodecError::InvalidFormat(
                "attribute name must be OCTET STRING".into(),
            ));
        }
        if attr_val.contains(&0) {
            return Err(CodecError::InvalidFormat(
                "embedded NULL byte in attribute name".into(),
            ));
        }
        let attr_str = String::from_utf8(attr_val.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;
        attributes.push(attr_str);
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(CodecError::InvalidFormat(
                "too many requested attributes".into(),
            ));
        }
    }

    Ok(SearchRequest {
        base_object,
        scope,
        deref_aliases,
        size_limit,
        time_limit,
        types_only,
        filter,
        attributes,
    })
}

/// Recursively decode a search filter.
pub fn decode_filter(tag: u8, value: &[u8], depth: usize) -> Result<Filter> {
    if depth >= MAX_FILTER_DEPTH {
        return Err(CodecError::InvalidFormat(
            "filter nesting exceeds maximum depth".into(),
        ));
    }

    match tag {
        TAG_CTX_0_CONSTRUCTED => {
            // AND — SET OF Filter
            let mut filters = Vec::new();
            let mut iter = TlvIter::new(value);
            while !iter.is_empty() {
                let (ftag, fval) = iter.next_tlv()?;
                filters.push(decode_filter(ftag, fval, depth + 1)?);
                if filters.len() > MAX_FILTER_CHILDREN {
                    return Err(CodecError::InvalidFormat(
                        "filter AND/OR set exceeds maximum children".into(),
                    ));
                }
            }
            Ok(Filter::And(filters))
        }
        TAG_CTX_1_CONSTRUCTED => {
            // OR — SET OF Filter
            let mut filters = Vec::new();
            let mut iter = TlvIter::new(value);
            while !iter.is_empty() {
                let (ftag, fval) = iter.next_tlv()?;
                filters.push(decode_filter(ftag, fval, depth + 1)?);
                if filters.len() > MAX_FILTER_CHILDREN {
                    return Err(CodecError::InvalidFormat(
                        "filter AND/OR set exceeds maximum children".into(),
                    ));
                }
            }
            Ok(Filter::Or(filters))
        }
        TAG_CTX_2_CONSTRUCTED => {
            // NOT — Filter
            let (ftag, fval, _) = decode_tlv(value)?;
            Ok(Filter::Not(Box::new(decode_filter(ftag, fval, depth + 1)?)))
        }
        TAG_CTX_3_CONSTRUCTED => {
            // equalityMatch — AttributeValueAssertion
            let ava = decode_attribute_value_assertion(value)?;
            Ok(Filter::EqualityMatch(ava))
        }
        TAG_CTX_4_CONSTRUCTED => {
            // substrings — SubstringFilter
            let sf = decode_substring_filter(value)?;
            Ok(Filter::Substrings(sf))
        }
        TAG_CTX_7 => {
            // present — AttributeDescription (OCTET STRING value)
            let attr = String::from_utf8(value.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;
            Ok(Filter::Present(attr))
        }
        0xA8 => {
            // approxMatch [8] — AttributeValueAssertion
            let ava = decode_attribute_value_assertion(value)?;
            Ok(Filter::ApproxMatch(ava))
        }
        _ => Err(CodecError::InvalidFormat(format!(
            "unsupported filter tag 0x{tag:02x}"
        ))),
    }
}

/// Decode an AttributeValueAssertion from SEQUENCE contents.
fn decode_attribute_value_assertion(value: &[u8]) -> Result<AttributeValueAssertion> {
    let mut iter = TlvIter::new(value);
    let (desc_tag, desc_val) = iter.next_tlv()?;
    if desc_tag != TAG_OCTET_STRING {
        return Err(CodecError::InvalidFormat(
            "AVA attributeDesc must be OCTET STRING".into(),
        ));
    }
    // Reject embedded NULL bytes in attribute descriptions to prevent
    // filter comparison bypasses (C-string truncation attacks).
    if desc_val.contains(&0) {
        return Err(CodecError::InvalidFormat(
            "embedded NULL byte in AVA attributeDesc".into(),
        ));
    }
    let attribute_desc =
        String::from_utf8(desc_val.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;

    let (val_tag, val_val) = iter.next_tlv()?;
    if val_tag != TAG_OCTET_STRING {
        return Err(CodecError::InvalidFormat(
            "AVA assertionValue must be OCTET STRING".into(),
        ));
    }
    // Reject embedded NULL bytes in assertion values.
    if val_val.contains(&0) {
        return Err(CodecError::InvalidFormat(
            "embedded NULL byte in AVA assertionValue".into(),
        ));
    }
    Ok(AttributeValueAssertion {
        attribute_desc,
        assertion_value: val_val.to_vec(),
    })
}

/// Decode a SubstringFilter from its SEQUENCE contents.
fn decode_substring_filter(value: &[u8]) -> Result<SubstringFilter> {
    let mut iter = TlvIter::new(value);
    let (type_tag, type_val) = iter.next_tlv()?;
    if type_tag != TAG_OCTET_STRING {
        return Err(CodecError::InvalidFormat(
            "SubstringFilter type must be OCTET STRING".into(),
        ));
    }
    if type_val.contains(&0) {
        return Err(CodecError::InvalidFormat(
            "embedded NULL byte in SubstringFilter attribute".into(),
        ));
    }
    let attribute_desc =
        String::from_utf8(type_val.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;

    // substrings SEQUENCE OF CHOICE { initial [0], any [1], final [2] }
    let (seq_tag, seq_val) = iter.next_tlv()?;
    if seq_tag != TAG_SEQUENCE {
        return Err(CodecError::InvalidFormat(
            "SubstringFilter substrings must be SEQUENCE".into(),
        ));
    }

    let mut initial = None;
    let mut any = Vec::new();
    let mut final_value = None;
    let mut sub_iter = TlvIter::new(seq_val);
    while !sub_iter.is_empty() {
        let (stag, sval) = sub_iter.next_tlv()?;
        match stag {
            0x80 => initial = Some(sval.to_vec()), // [0] initial
            0x81 => {
                any.push(sval.to_vec());
                if any.len() > MAX_SUBSTRING_ANY {
                    return Err(CodecError::InvalidFormat(
                        "too many substring 'any' components".into(),
                    ));
                }
            }
            0x82 => final_value = Some(sval.to_vec()), // [2] final
            _ => {
                return Err(CodecError::InvalidFormat(format!(
                    "unexpected substring choice tag 0x{stag:02x}"
                )));
            }
        }
    }

    Ok(SubstringFilter {
        attribute_desc,
        initial,
        any,
        final_value,
    })
}

/// Decode an ExtendedRequest from its value bytes.
///
/// ```text
/// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
///     requestName  [0] LDAPOID,
///     requestValue [1] OCTET STRING OPTIONAL
/// }
/// ```
fn decode_extended_request(value: &[u8]) -> Result<ExtendedRequest> {
    let mut iter = TlvIter::new(value);

    // requestName [0]
    let (name_tag, name_val) = iter.next_tlv()?;
    if name_tag != TAG_CTX_0 {
        return Err(CodecError::InvalidFormat(format!(
            "ExtendedRequest requestName expected tag 0x80, got 0x{name_tag:02x}"
        )));
    }
    let request_name = String::from_utf8(name_val.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;

    // requestValue [1] OPTIONAL
    let request_value = if !iter.is_empty() {
        let (val_tag, val_val) = iter.next_tlv()?;
        if val_tag != 0x81 {
            return Err(CodecError::InvalidFormat(format!(
                "ExtendedRequest requestValue expected tag 0x81, got 0x{val_tag:02x}"
            )));
        }
        Some(val_val.to_vec())
    } else {
        None
    };

    Ok(ExtendedRequest {
        request_name,
        request_value,
    })
}

// ---------------------------------------------------------------------------
// High-level LDAP message encoding
// ---------------------------------------------------------------------------

/// Encode an LDAPMessage to wire bytes.
pub fn encode_ldap_message(msg: &LdapMessage) -> Result<Vec<u8>> {
    let msg_id_bytes = encode_integer(msg.message_id as i64);
    let op_bytes = encode_protocol_op(&msg.protocol_op)?;

    let mut contents = Vec::with_capacity(msg_id_bytes.len() + op_bytes.len());
    contents.extend_from_slice(&msg_id_bytes);
    contents.extend_from_slice(&op_bytes);

    Ok(encode_sequence(&contents))
}

/// Encode a protocol operation with its application tag.
fn encode_protocol_op(op: &ProtocolOp) -> Result<Vec<u8>> {
    match op {
        ProtocolOp::BindRequest(req) => encode_bind_request(req),
        ProtocolOp::BindResponse(resp) => encode_bind_response(resp),
        ProtocolOp::UnbindRequest => Ok(encode_tlv(TAG_UNBIND_REQUEST, &[])),
        ProtocolOp::SearchRequest(req) => encode_search_request(req),
        ProtocolOp::SearchResultEntry(entry) => encode_search_result_entry(entry),
        ProtocolOp::SearchResultDone(result) => Ok(encode_tlv(
            TAG_SEARCH_RESULT_DONE,
            &encode_ldap_result_contents(result),
        )),
        ProtocolOp::ExtendedRequest(req) => encode_extended_request(req),
        ProtocolOp::ExtendedResponse(resp) => encode_extended_response(resp),
    }
}

/// Encode the inner contents of an LdapResult (shared by many response types).
fn encode_ldap_result_contents(result: &LdapResult) -> Vec<u8> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_enumerated(result.result_code as i64));
    contents.extend_from_slice(&encode_octet_string(result.matched_dn.as_bytes()));
    contents.extend_from_slice(&encode_octet_string(result.diagnostic_message.as_bytes()));
    contents
}

fn encode_bind_request(req: &BindRequest) -> Result<Vec<u8>> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_integer(req.version as i64));
    contents.extend_from_slice(&encode_octet_string(req.name.as_bytes()));
    match &req.authentication {
        AuthChoice::Simple(password) => {
            contents.extend_from_slice(&encode_tlv(TAG_CTX_0, password));
        }
        AuthChoice::Sasl => {
            // We never encode outbound SASL, but handle it for completeness.
            return Err(CodecError::InvalidFormat(
                "SASL encoding not supported".into(),
            ));
        }
    }
    Ok(encode_tlv(TAG_BIND_REQUEST, &contents))
}

fn encode_bind_response(resp: &BindResponse) -> Result<Vec<u8>> {
    let contents = encode_ldap_result_contents(&resp.result);
    Ok(encode_tlv(TAG_BIND_RESPONSE, &contents))
}

fn encode_search_request(req: &SearchRequest) -> Result<Vec<u8>> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_octet_string(req.base_object.as_bytes()));
    contents.extend_from_slice(&encode_enumerated(req.scope as i64));
    contents.extend_from_slice(&encode_enumerated(req.deref_aliases as i64));
    contents.extend_from_slice(&encode_integer(req.size_limit as i64));
    contents.extend_from_slice(&encode_integer(req.time_limit as i64));
    contents.extend_from_slice(&encode_boolean(req.types_only));
    contents.extend_from_slice(&encode_filter(&req.filter));

    // attributes: SEQUENCE OF LDAPString
    let mut attrs_contents = Vec::new();
    for attr in &req.attributes {
        attrs_contents.extend_from_slice(&encode_octet_string(attr.as_bytes()));
    }
    contents.extend_from_slice(&encode_sequence(&attrs_contents));

    Ok(encode_tlv(TAG_SEARCH_REQUEST, &contents))
}

/// Encode a search filter.
fn encode_filter(filter: &Filter) -> Vec<u8> {
    match filter {
        Filter::And(filters) => {
            let mut contents = Vec::new();
            for f in filters {
                contents.extend_from_slice(&encode_filter(f));
            }
            encode_tlv(TAG_CTX_0_CONSTRUCTED, &contents)
        }
        Filter::Or(filters) => {
            let mut contents = Vec::new();
            for f in filters {
                contents.extend_from_slice(&encode_filter(f));
            }
            encode_tlv(TAG_CTX_1_CONSTRUCTED, &contents)
        }
        Filter::Not(filter) => {
            let inner = encode_filter(filter);
            encode_tlv(TAG_CTX_2_CONSTRUCTED, &inner)
        }
        Filter::EqualityMatch(ava) => encode_tlv(TAG_CTX_3_CONSTRUCTED, &encode_ava(ava)),
        Filter::Substrings(sf) => encode_tlv(TAG_CTX_4_CONSTRUCTED, &encode_substring_filter(sf)),
        Filter::Present(attr) => encode_tlv(TAG_CTX_7, attr.as_bytes()),
        Filter::ApproxMatch(ava) => encode_tlv(0xA8, &encode_ava(ava)),
    }
}

fn encode_ava(ava: &AttributeValueAssertion) -> Vec<u8> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_octet_string(ava.attribute_desc.as_bytes()));
    contents.extend_from_slice(&encode_octet_string(&ava.assertion_value));
    contents
}

fn encode_substring_filter(sf: &SubstringFilter) -> Vec<u8> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_octet_string(sf.attribute_desc.as_bytes()));

    let mut subs = Vec::new();
    if let Some(initial) = &sf.initial {
        subs.extend_from_slice(&encode_tlv(0x80, initial));
    }
    for any in &sf.any {
        subs.extend_from_slice(&encode_tlv(0x81, any));
    }
    if let Some(fin) = &sf.final_value {
        subs.extend_from_slice(&encode_tlv(0x82, fin));
    }
    contents.extend_from_slice(&encode_sequence(&subs));
    contents
}

fn encode_search_result_entry(entry: &SearchResultEntry) -> Result<Vec<u8>> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_octet_string(entry.object_name.as_bytes()));

    // attributes: SEQUENCE OF PartialAttribute
    let mut attrs_contents = Vec::new();
    for attr in &entry.attributes {
        let mut attr_contents = Vec::new();
        attr_contents.extend_from_slice(&encode_octet_string(attr.attr_type.as_bytes()));
        let mut vals = Vec::new();
        for val in &attr.values {
            vals.extend_from_slice(&encode_octet_string(val));
        }
        attr_contents.extend_from_slice(&encode_set(&vals));
        attrs_contents.extend_from_slice(&encode_sequence(&attr_contents));
    }
    contents.extend_from_slice(&encode_sequence(&attrs_contents));

    Ok(encode_tlv(TAG_SEARCH_RESULT_ENTRY, &contents))
}

fn encode_extended_request(req: &ExtendedRequest) -> Result<Vec<u8>> {
    let mut contents = Vec::new();
    contents.extend_from_slice(&encode_tlv(TAG_CTX_0, req.request_name.as_bytes()));
    if let Some(val) = &req.request_value {
        contents.extend_from_slice(&encode_tlv(0x81, val));
    }
    Ok(encode_tlv(TAG_EXTENDED_REQUEST, &contents))
}

fn encode_extended_response(resp: &ExtendedResponse) -> Result<Vec<u8>> {
    let mut contents = encode_ldap_result_contents(&resp.result);
    if let Some(name) = &resp.response_name {
        contents.extend_from_slice(&encode_tlv(0x8A, name.as_bytes()));
    }
    if let Some(val) = &resp.response_value {
        contents.extend_from_slice(&encode_tlv(0x8B, val));
    }
    Ok(encode_tlv(TAG_EXTENDED_RESPONSE, &contents))
}

// ---------------------------------------------------------------------------
// Framing codec for stream-oriented transport
// ---------------------------------------------------------------------------

/// A stateless LDAPv3 message framer.
///
/// LDAP messages are self-delimiting BER SEQUENCE TLVs. The codec reads the
/// outer SEQUENCE tag + length to determine message boundaries, then decodes
/// the full message once enough bytes are available.
#[must_use]
pub struct LdapCodec;

impl LdapCodec {
    /// Create a new codec instance.
    pub fn new() -> Self {
        Self
    }

    /// Attempt to extract a complete LDAPMessage from the front of `buf`.
    ///
    /// Returns `Ok(Some((msg, consumed)))` if a full message was decoded,
    /// `Ok(None)` if more bytes are needed, or `Err` on malformed data.
    pub fn decode_frame(&self, buf: &[u8]) -> Result<Option<(LdapMessage, usize)>> {
        if buf.is_empty() {
            return Ok(None);
        }

        // Peek at outer SEQUENCE tag + length to determine total message size.
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

        // NIST SI-10: Reject oversized messages to prevent memory exhaustion.
        if content_len > MAX_MESSAGE_SIZE {
            return Err(CodecError::InvalidFormat(format!(
                "message size {} exceeds maximum {}",
                content_len, MAX_MESSAGE_SIZE
            )));
        }

        if buf.len() < total_len {
            return Ok(None); // Need more bytes.
        }

        let (msg, consumed) = decode_ldap_message(buf)?;
        debug_assert_eq!(consumed, total_len);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_length_short() {
        let encoded = encode_length(42);
        assert_eq!(encoded, vec![42]);
        let (decoded, consumed) = decode_length(&encoded).unwrap();
        assert_eq!(decoded, 42);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_encode_decode_length_long() {
        let encoded = encode_length(300);
        assert_eq!(encoded, vec![0x82, 0x01, 0x2C]);
        let (decoded, consumed) = decode_length(&encoded).unwrap();
        assert_eq!(decoded, 300);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_encode_decode_integer() {
        for val in &[0i64, 1, -1, 127, 128, -128, 256, 100_000, -100_000] {
            let encoded = encode_integer(*val);
            let (decoded, _) = decode_integer(&encoded).unwrap();
            assert_eq!(decoded, *val, "round-trip failed for {val}");
        }
    }

    #[test]
    fn test_encode_decode_boolean() {
        let t = encode_boolean(true);
        let f = encode_boolean(false);
        assert!(decode_boolean(&t).unwrap().0);
        assert!(!decode_boolean(&f).unwrap().0);
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let val = b"hello";
        let encoded = encode_octet_string(val);
        let (decoded, _) = decode_octet_string(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_bind_request_round_trip() {
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: "cn=admin,dc=example,dc=com".into(),
                authentication: AuthChoice::Simple(b"secret".to_vec()),
            }),
        };
        let encoded = encode_ldap_message(&msg).unwrap();
        let (decoded, consumed) = decode_ldap_message(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.message_id, 1);
        match &decoded.protocol_op {
            ProtocolOp::BindRequest(req) => {
                assert_eq!(req.version, 3);
                assert_eq!(req.name, "cn=admin,dc=example,dc=com");
                match &req.authentication {
                    AuthChoice::Simple(pw) => assert_eq!(pw, b"secret"),
                    _ => panic!("expected simple auth"),
                }
            }
            _ => panic!("expected BindRequest"),
        }
    }

    #[test]
    fn test_bind_response_round_trip() {
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindResponse(BindResponse {
                result: LdapResult {
                    result_code: ResultCode::Success,
                    matched_dn: String::new(),
                    diagnostic_message: String::new(),
                },
            }),
        };
        let encoded = encode_ldap_message(&msg).unwrap();
        // BindResponse is a server→client message; we verify it encodes without error.
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_search_result_entry_encodes() {
        let entry = SearchResultEntry {
            object_name: "cn=jdoe,ou=users,dc=example,dc=com".into(),
            attributes: vec![PartialAttribute {
                attr_type: "cn".into(),
                values: vec![b"jdoe".to_vec()],
            }],
        };
        let msg = LdapMessage {
            message_id: 2,
            protocol_op: ProtocolOp::SearchResultEntry(entry),
        };
        let encoded = encode_ldap_message(&msg).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_codec_frame_incomplete() {
        let codec = LdapCodec::new();
        // An incomplete message (just the SEQUENCE tag)
        assert!(codec.decode_frame(&[0x30]).unwrap().is_none());
        assert!(codec.decode_frame(&[]).unwrap().is_none());
    }

    #[test]
    fn test_message_size_limit_enforced() {
        let codec = LdapCodec::new();
        // Build a fake SEQUENCE with a massive content_len claim.
        // 0x30 0x84 0xFF 0xFF 0xFF 0xFF = SEQUENCE with ~4GB length
        let oversized = vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = codec.decode_frame(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_depth_limit_enforced() {
        // Build a deeply nested NOT(NOT(NOT(...))) filter.
        // Each NOT is TAG_CTX_2_CONSTRUCTED wrapping another NOT.
        fn build_nested_not(depth: usize) -> Vec<u8> {
            if depth == 0 {
                // Leaf: present filter (objectClass)
                let attr = b"objectClass";
                encode_tlv(TAG_CTX_7, attr)
            } else {
                let inner = build_nested_not(depth - 1);
                encode_tlv(TAG_CTX_2_CONSTRUCTED, &inner)
            }
        }
        let deep_filter = build_nested_not(MAX_FILTER_DEPTH + 5);
        // Try to decode — should fail with depth error.
        let (tag, value, _) = decode_tlv(&deep_filter).unwrap();
        let result = decode_filter(tag, value, 0);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_integer_round_trip(val in proptest::num::i64::ANY) {
            let encoded = encode_integer(val);
            let (decoded, consumed) = decode_integer(&encoded).unwrap();
            prop_assert_eq!(decoded, val);
            prop_assert_eq!(consumed, encoded.len());
        }

        #[test]
        fn prop_length_round_trip(len in 0usize..MAX_MESSAGE_SIZE) {
            let encoded = encode_length(len);
            let (decoded, consumed) = decode_length(&encoded).unwrap();
            prop_assert_eq!(decoded, len);
            prop_assert_eq!(consumed, encoded.len());
        }

        #[test]
        fn prop_octet_string_round_trip(data in proptest::collection::vec(proptest::num::u8::ANY, 0..4096)) {
            let encoded = encode_octet_string(&data);
            let (decoded, consumed) = decode_octet_string(&encoded).unwrap();
            prop_assert_eq!(decoded, data);
            prop_assert_eq!(consumed, encoded.len());
        }

        #[test]
        fn prop_boolean_round_trip(val: bool) {
            let encoded = encode_boolean(val);
            let (decoded, consumed) = decode_boolean(&encoded).unwrap();
            prop_assert_eq!(decoded, val);
            prop_assert_eq!(consumed, encoded.len());
        }

        #[test]
        fn prop_enumerated_round_trip(val in 0i64..256) {
            let encoded = encode_enumerated(val);
            let (decoded, consumed) = decode_enumerated(&encoded).unwrap();
            prop_assert_eq!(decoded, val);
            prop_assert_eq!(consumed, encoded.len());
        }

        #[test]
        fn prop_bind_request_round_trip(
            msg_id in 1i32..10000,
            dn in "[a-z]{2,10}=[a-z]{2,20},dc=[a-z]{3,10},dc=[a-z]{2,5}",
            password in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
        ) {
            let msg = LdapMessage {
                message_id: msg_id,
                protocol_op: ProtocolOp::BindRequest(BindRequest {
                    version: 3,
                    name: dn.clone(),
                    authentication: AuthChoice::Simple(password.clone()),
                }),
            };
            let encoded = encode_ldap_message(&msg).unwrap();
            let (decoded, consumed) = decode_ldap_message(&encoded).unwrap();
            prop_assert_eq!(consumed, encoded.len());
            prop_assert_eq!(decoded.message_id, msg_id);
            match decoded.protocol_op {
                ProtocolOp::BindRequest(req) => {
                    prop_assert_eq!(req.version, 3);
                    prop_assert_eq!(req.name, dn);
                    match req.authentication {
                        AuthChoice::Simple(pw) => prop_assert_eq!(pw, password),
                        _ => prop_assert!(false, "expected Simple auth"),
                    }
                }
                _ => prop_assert!(false, "expected BindRequest"),
            }
        }

        #[test]
        fn prop_decode_never_panics_on_random_input(data in proptest::collection::vec(proptest::num::u8::ANY, 0..1024)) {
            // This is the most important property: the codec must never panic on arbitrary input.
            let codec = LdapCodec::new();
            let _ = codec.decode_frame(&data);
        }

        #[test]
        fn prop_decode_filter_never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 1..512)) {
            let tag = data[0];
            let _ = decode_filter(tag, &data[1..], 0);
        }
    }
}
