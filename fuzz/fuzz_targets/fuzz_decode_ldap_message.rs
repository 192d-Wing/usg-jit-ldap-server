#![no_main]
use libfuzzer_sys::fuzz_target;
use usg_jit_ldap_server::ldap::codec::decode_ldap_message;

fuzz_target!(|data: &[u8]| {
    let _ = decode_ldap_message(data);
});
