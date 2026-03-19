//! USG JIT LDAP Server entry point.
//!
//! Initializes configuration, logging, TLS, database connections,
//! and starts the LDAP listener.

mod auth;
mod audit;
mod config;
mod db;
mod ldap;
mod replication;
mod tls;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .init();

    tracing::info!("USG JIT LDAP Server starting...");

    // TODO: load config, init TLS, connect to DB, start listener
}
