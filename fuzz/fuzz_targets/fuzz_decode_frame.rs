#![no_main]
use libfuzzer_sys::fuzz_target;
use usg_jit_ldap_server::ldap::codec::LdapCodec;

fuzz_target!(|data: &[u8]| {
    let codec = LdapCodec::new();
    let _ = codec.decode_frame(data);
});
