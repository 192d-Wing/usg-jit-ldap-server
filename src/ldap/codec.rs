//! BER / ASN.1 codec for LDAP messages.
//!
//! Encodes and decodes LDAP PDUs on the wire using `rasn` /
//! `rasn-ldap`.  Implements a tokio codec for framing.

/// Placeholder codec that will implement `tokio_util::codec::Decoder`
/// and `Encoder` for LDAP messages.
pub struct LdapCodec;

impl LdapCodec {
    pub fn new() -> Self {
        Self
    }
}
