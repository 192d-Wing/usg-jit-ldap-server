#![no_main]
use libfuzzer_sys::fuzz_target;
use usg_jit_ldap_server::ldap::codec::decode_length;

fuzz_target!(|data: &[u8]| {
    let _ = decode_length(data);
});
