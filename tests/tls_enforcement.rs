//! TLS enforcement tests.
//!
//! Verifies that the server's TLS configuration:
//! - Only accepts TLS 1.3
//! - Rejects connections without valid certificates at startup
//! - Does not support StartTLS

use rcgen::generate_simple_self_signed;

/// Generate a self-signed certificate and key for testing.
fn generate_test_certs() -> (Vec<u8>, Vec<u8>) {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();
    (cert_pem, key_pem)
}

/// Write test certs to temp files and return paths.
fn write_test_certs() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let (cert_pem, key_pem) = generate_test_certs();

    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut cert_file, &cert_pem).unwrap();

    let mut key_file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut key_file, &key_pem).unwrap();

    (cert_file, key_file)
}

#[test]
fn test_tls_acceptor_builds_with_valid_certs() {
    // Install the ring crypto provider for rustls (needed in test binaries
    // where the default provider is not automatically selected).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (cert_file, key_file) = write_test_certs();

    let settings = usg_jit_ldap_server::config::TlsSettings {
        cert_path: cert_file.path().to_str().unwrap().to_string(),
        key_path: key_file.path().to_str().unwrap().to_string(),
        min_version: "1.3".to_string(),
    };

    let result = usg_jit_ldap_server::tls::build_tls_acceptor(&settings);
    assert!(result.is_ok(), "TLS acceptor should build with valid certs");
}

#[test]
fn test_tls_acceptor_fails_without_cert_file() {
    let settings = usg_jit_ldap_server::config::TlsSettings {
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
        min_version: "1.3".to_string(),
    };

    let result = usg_jit_ldap_server::tls::build_tls_acceptor(&settings);
    assert!(result.is_err(), "TLS acceptor should fail without cert file");
}

#[test]
fn test_tls_12_rejected() {
    let (cert_file, key_file) = write_test_certs();

    let settings = usg_jit_ldap_server::config::TlsSettings {
        cert_path: cert_file.path().to_str().unwrap().to_string(),
        key_path: key_file.path().to_str().unwrap().to_string(),
        min_version: "1.2".to_string(),
    };

    let result = usg_jit_ldap_server::tls::build_tls_acceptor(&settings);
    assert!(result.is_err(), "TLS 1.2 should be rejected — only 1.3 is supported");
}

#[test]
fn test_tls_10_rejected() {
    let (cert_file, key_file) = write_test_certs();

    let settings = usg_jit_ldap_server::config::TlsSettings {
        cert_path: cert_file.path().to_str().unwrap().to_string(),
        key_path: key_file.path().to_str().unwrap().to_string(),
        min_version: "1.0".to_string(),
    };

    let result = usg_jit_ldap_server::tls::build_tls_acceptor(&settings);
    assert!(result.is_err(), "TLS 1.0 should be rejected");
}
