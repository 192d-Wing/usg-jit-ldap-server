//! TLS acceptor setup using rustls.
//!
//! Loads server certificates and private keys from PEM files,
//! optionally configures client-certificate (mTLS) verification,
//! and produces a `TlsAcceptor` for the LDAP listener.

use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Build a `TlsAcceptor` from the paths specified in configuration.
pub fn build_tls_acceptor(
    _cert_path: &str,
    _key_path: &str,
    _ca_path: Option<&str>,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    // TODO: read PEM files, build rustls ServerConfig, wrap in TlsAcceptor
    todo!("TLS acceptor setup")
}

/// Placeholder for TLS-related helpers (e.g., certificate reloading).
pub struct TlsState {
    pub acceptor: Arc<TlsAcceptor>,
}
