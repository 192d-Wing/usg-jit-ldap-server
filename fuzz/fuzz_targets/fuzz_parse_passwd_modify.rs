#![no_main]
use libfuzzer_sys::fuzz_target;
use usg_jit_ldap_server::ldap::password::parse_passwd_modify_request;

fuzz_target!(|data: &[u8]| {
    let _ = parse_passwd_modify_request(data);
});
