#![no_main]
use libfuzzer_sys::fuzz_target;
use usg_jit_ldap_server::ldap::codec::decode_filter;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() { return; }
    let tag = data[0];
    let _ = decode_filter(tag, &data[1..], 0);
});
