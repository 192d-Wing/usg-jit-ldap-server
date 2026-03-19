//! Configuration loading and validation.
//!
//! Reads `config.toml` (or a path given via CLI / env) and produces
//! a strongly-typed `ServerConfig` consumed by the rest of the server.

use serde::Deserialize;

/// Top-level server configuration.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub tls: TlsSection,
    pub database: DatabaseSection,
    pub replication: ReplicationSection,
    pub security: SecuritySection,
    pub audit: AuditSection,
}

#[derive(Debug, Deserialize)]
pub struct ServerSection {
    pub bind_addr: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct TlsSection {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseSection {
    pub url: String,
    pub max_connections: u32,
    pub identity_schema: String,
    pub runtime_schema: String,
}

#[derive(Debug, Deserialize)]
pub struct ReplicationSection {
    pub enabled: bool,
    pub central_url: Option<String>,
    pub pull_interval_secs: u64,
    pub site_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SecuritySection {
    pub max_bind_attempts: u32,
    pub rate_limit_window_secs: u64,
    pub password_ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuditSection {
    pub enabled: bool,
    pub log_path: Option<String>,
}

/// Load configuration from a TOML file at the given path.
pub fn load_config(path: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(path)?;
    let config: ServerConfig = toml::from_str(&contents)?;
    Ok(config)
}
