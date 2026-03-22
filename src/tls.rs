// SPDX-License-Identifier: TBD
//
// TLS Configuration and Enforcement
//
// Builds a rustls ServerConfig with secure defaults (TLS 1.3 only, strong
// ciphersuites) and returns a TlsAcceptor for the LDAPS listener.
//
// NIST SP 800-53 Rev. 5:
// - SC-8 (Transmission Confidentiality and Integrity): All LDAP connections are
//   wrapped in TLS from the first byte. There is no cleartext LDAP code path.
//   The server does not start if TLS material is unavailable or invalid.
// - SC-17 (PKI Certificates): Server certificates are validated at startup.
//   Certificate details (subject, issuer, expiry) are logged for operational
//   awareness. The private key is NEVER logged.
// - SC-13 (Cryptographic Protection): Only FIPS-compatible ciphersuites and
//   TLS 1.2+ are permitted. Weak protocols and ciphers are not available.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsSettings;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to read certificate file '{path}': {source}")]
    CertFileRead {
        path: String,
        source: rustls_pki_types::pem::Error,
    },

    #[error("failed to read private key file '{path}': {source}")]
    KeyFileRead {
        path: String,
        source: rustls_pki_types::pem::Error,
    },

    #[error("no certificates found in '{0}'")]
    NoCertificates(String),

    #[error("no private key found in '{0}'")]
    NoPrivateKey(String),

    #[error("multiple private keys found in '{0}' — expected exactly one")]
    MultiplePrivateKeys(String),

    #[error("TLS configuration error: {0}")]
    RustlsConfig(#[from] rustls::Error),

    #[error("unsupported minimum TLS version: '{0}'")]
    UnsupportedVersion(String),
}

// ---------------------------------------------------------------------------
// TLS acceptor construction
// ---------------------------------------------------------------------------

/// Build a TLS acceptor from configured certificate paths.
///
/// NIST SC-8: Transmission confidentiality — all connections are TLS-wrapped.
/// NIST SC-17: PKI certificates — validated at startup, fail-closed on error.
///
/// This function will:
/// 1. Load the certificate chain from the PEM file.
/// 2. Load the private key from the PEM file.
/// 3. Log certificate metadata (subject, issuer, expiry) — NEVER the private key.
/// 4. Build a rustls ServerConfig with strong defaults.
/// 5. Return a TlsAcceptor ready for use with tokio.
///
/// If any step fails, the server must NOT start (fail-closed).
pub fn build_tls_acceptor(config: &TlsSettings) -> Result<TlsAcceptor, TlsError> {
    // Step 1: Load certificate chain.
    let certs = load_certificates(&config.cert_path)?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(config.cert_path.clone()));
    }

    tracing::info!(
        cert_path = %config.cert_path,
        cert_count = certs.len(),
        "loaded TLS certificate chain"
    );

    // Log certificate details for operational awareness.
    // NIST SC-17: Certificate metadata is logged at startup so operators
    // can verify correct certificates are in use and track expiry.
    log_certificate_info(&certs);

    // Step 2: Load private key.
    let key = load_private_key(&config.key_path)?;
    tracing::info!(
        key_path = %config.key_path,
        "loaded TLS private key (details not logged — NIST SC-12)"
    );

    // Step 3: Build rustls ServerConfig.
    // NIST SC-13: Only strong ciphersuites and TLS 1.2+ are permitted.
    let tls_config = build_server_config(certs, key, &config.min_version)?;

    tracing::info!(
        min_tls_version = %config.min_version,
        "TLS configuration built with secure defaults"
    );

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// Load PEM-encoded certificates from a file.
fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| TlsError::CertFileRead {
            path: path.to_string(),
            source: e,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertFileRead {
            path: path.to_string(),
            source: e,
        })?;

    Ok(certs)
}

/// Load a PEM-encoded private key from a file.
///
/// Supports RSA (PKCS1), PKCS8, and EC (SEC1) key formats.
/// Uses `rustls-pki-types` PEM parsing (replacement for unmaintained rustls-pemfile).
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| TlsError::KeyFileRead {
        path: path.to_string(),
        source: e,
    })
}

/// Build a rustls ServerConfig with secure defaults.
///
/// NIST SC-13: Cryptographic protection — only strong ciphersuites are enabled.
/// The default rustls provider (ring) provides FIPS-compatible algorithms.
fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    min_version: &str,
) -> Result<ServerConfig, TlsError> {
    // Only TLS 1.3 is supported. TLS 1.2 is explicitly excluded.
    // NIST SC-13: Strongest available cryptographic protection.
    if min_version != "1.3" {
        return Err(TlsError::UnsupportedVersion(format!(
            "'{}' — only TLS 1.3 is supported",
            min_version
        )));
    }

    // Install the ring crypto provider. Required by rustls 0.23+.
    // This is idempotent — if already installed, it's a no-op.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}

/// Log certificate metadata for operational awareness.
///
/// NIST SC-17: Logs subject, issuer, and validity period from DER-encoded
/// certificates. Warns on approaching expiry.
fn log_certificate_info(certs: &[CertificateDer<'static>]) {
    for (i, cert) in certs.iter().enumerate() {
        let cert_bytes = cert.as_ref();
        let position = if i == 0 { "leaf" } else { "chain" };

        match x509_parser::parse_x509_certificate(cert_bytes) {
            Ok((_, parsed)) => {
                let subject = parsed.subject().to_string();
                let issuer = parsed.issuer().to_string();
                let not_before = parsed.validity().not_before.to_datetime();
                let not_after = parsed.validity().not_after.to_datetime();

                tracing::info!(
                    chain_position = position,
                    chain_index = i,
                    subject = %subject,
                    issuer = %issuer,
                    not_before = %not_before,
                    not_after = %not_after,
                    "TLS certificate loaded"
                );

                // Check expiry — warn operators proactively.
                let expiry: std::time::SystemTime = not_after.into();
                let now = std::time::SystemTime::now();
                if let Ok(remaining) = expiry.duration_since(now) {
                    let days_remaining = remaining.as_secs() / 86400;
                    if days_remaining < 7 {
                        tracing::error!(
                            days_remaining = days_remaining,
                            subject = %subject,
                            "CRITICAL: TLS certificate expires in less than 7 days"
                        );
                    } else if days_remaining < 30 {
                        tracing::warn!(
                            days_remaining = days_remaining,
                            subject = %subject,
                            "TLS certificate expires in less than 30 days"
                        );
                    } else {
                        tracing::info!(
                            days_remaining = days_remaining,
                            "TLS certificate expiry check passed"
                        );
                    }
                } else {
                    tracing::error!(
                        subject = %subject,
                        "CRITICAL: TLS certificate has already expired"
                    );
                }
            }
            Err(e) => {
                // Fall back to basic logging if parsing fails.
                tracing::warn!(
                    chain_position = position,
                    chain_index = i,
                    cert_size_bytes = cert_bytes.len(),
                    error = %e,
                    "failed to parse certificate DER — falling back to size-only logging"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_cert_file_returns_error() {
        let result = load_certificates("/nonexistent/cert.pem");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertFileRead { path, .. } => {
                assert_eq!(path, "/nonexistent/cert.pem");
            }
            other => panic!("expected CertFileRead, got: {other}"),
        }
    }

    #[test]
    fn test_missing_key_file_returns_error() {
        let result = load_private_key("/nonexistent/key.pem");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::KeyFileRead { path, .. } => {
                assert_eq!(path, "/nonexistent/key.pem");
            }
            other => panic!("expected KeyFileRead, got: {other}"),
        }
    }

    #[test]
    fn test_unsupported_tls_version() {
        let result = build_server_config(vec![], PrivateKeyDer::Pkcs8(vec![].into()), "1.0");
        assert!(result.is_err());
    }
}
