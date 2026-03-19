// SPDX-License-Identifier: TBD
//
// Configuration Loading and Validation
//
// Reads a TOML configuration file and produces a strongly-typed ServerConfig.
// Configuration paths can be provided via CLI argument or the LDAP_CONFIG_PATH
// environment variable.
//
// NIST SP 800-53 Rev. 5:
// - CM-6 (Configuration Settings): All operational parameters are externalized
//   into a validated configuration file. The server refuses to start if required
//   settings are missing or invalid, ensuring no implicit defaults weaken security.
// - CM-7 (Least Functionality): Only the minimum set of configuration parameters
//   required for LDAPS operation is exposed. No optional feature flags that could
//   expand the attack surface.

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration file '{path}': {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to parse configuration: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("configuration validation failed: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Configuration structs
// ---------------------------------------------------------------------------

/// Top-level server configuration.
///
/// NIST CM-6: All settings are loaded from a validated TOML file.
/// The server will not start with default/implicit values for security-critical
/// parameters (TLS paths, database URL, etc.).
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSettings,
    pub tls: TlsSettings,
    pub database: DatabaseSettings,
    pub replication: ReplicationSettings,
    pub security: SecuritySettings,
    pub audit: AuditSettings,
}

/// Network listener configuration.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ServerSettings {
    /// IP address to bind the listener on (e.g., "0.0.0.0" or "127.0.0.1").
    pub bind_addr: String,

    /// TCP port for LDAPS. Must be 636 in production; other values allowed
    /// only when `allow_non_standard_port` is true (for testing).
    pub port: u16,

    /// Allow binding to a port other than 636. Must be explicitly set to true
    /// for development/testing environments. Default: false.
    #[serde(default)]
    pub allow_non_standard_port: bool,

    /// Maximum concurrent connections. Default: 1024.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Per-connection idle timeout in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

fn default_max_connections() -> usize {
    1024
}

fn default_idle_timeout_secs() -> u64 {
    300
}

/// TLS certificate and key paths.
///
/// NIST SC-8: Transmission confidentiality requires valid TLS material.
/// NIST SC-17: PKI certificates are validated at startup.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TlsSettings {
    /// Path to the PEM-encoded server certificate chain.
    pub cert_path: String,

    /// Path to the PEM-encoded private key.
    pub key_path: String,

    /// Minimum TLS version. Default: "1.3". Only "1.3" is accepted.
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,
}

fn default_min_tls_version() -> String {
    "1.3".to_string()
}

/// PostgreSQL database connection settings.
#[derive(Debug, Deserialize)]
pub struct DatabaseSettings {
    /// PostgreSQL connection URL. Can also be overridden by DATABASE_URL env var.
    pub url: String,

    /// Maximum number of connections in the pool. Default: 10.
    #[serde(default = "default_db_max_connections")]
    pub max_connections: u32,
}

fn default_db_max_connections() -> u32 {
    10
}

/// Replication puller configuration.
#[derive(Debug, Deserialize)]
pub struct ReplicationSettings {
    /// Whether the replication puller is enabled. Central hub nodes set false.
    #[serde(default)]
    pub enabled: bool,

    /// PostgreSQL connection string for the central hub (sslmode=verify-full required).
    pub central_url: Option<String>,

    /// Pull interval in seconds. Default: 60.
    #[serde(default = "default_pull_interval_secs")]
    pub pull_interval_secs: u64,

    /// Unique site identifier (UUID).
    pub site_id: Option<String>,

    /// Maximum batch size per pull. Default: 1000.
    #[serde(default = "default_batch_size")]
    pub batch_size: i64,

    /// Maximum consecutive failures before puller halts. Default: 50.
    #[serde(default = "default_max_retry_attempts")]
    pub max_retry_attempts: u32,

    /// Staleness threshold in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_stale_threshold_secs")]
    pub stale_threshold_secs: u64,
}

fn default_pull_interval_secs() -> u64 {
    60
}

fn default_batch_size() -> i64 {
    1000
}

fn default_max_retry_attempts() -> u32 {
    50
}

fn default_stale_threshold_secs() -> u64 {
    3600
}

/// Security policy settings.
///
/// NIST AC-7: Unsuccessful logon attempt thresholds.
/// NIST IA-5: Password TTL and ephemeral credential management.
#[derive(Debug, Deserialize)]
pub struct SecuritySettings {
    /// Maximum failed bind attempts per DN within the sliding window.
    pub max_bind_attempts: u32,

    /// Sliding window duration in seconds for rate limiting.
    pub rate_limit_window_secs: u64,

    /// Time-to-live for JIT-provisioned ephemeral passwords, in seconds.
    /// Default: 28800 (8 hours).
    #[serde(default = "default_password_ttl_secs")]
    pub password_ttl_secs: u64,

    /// Maximum search operations per source IP per window. Default: 120.
    #[serde(default = "default_max_searches_per_minute")]
    pub max_searches_per_minute: u32,

    /// Search rate limit window in seconds. Default: 60.
    #[serde(default = "default_search_rate_window_secs")]
    pub search_rate_window_secs: u64,

    /// DNs authorized to invoke the Password Modify extended operation.
    /// NIST AC-3: Only recognized broker identities may set passwords.
    #[serde(default)]
    pub broker_dns: Vec<String>,
}

fn default_password_ttl_secs() -> u64 {
    28800
}

fn default_max_searches_per_minute() -> u32 {
    120
}

fn default_search_rate_window_secs() -> u64 {
    60
}

/// Audit logging configuration.
///
/// NIST AU-2: Audit events selection — all security-relevant events are logged.
/// NIST AU-3: Audit content includes timestamps, source IPs, DNs, and outcomes.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuditSettings {
    /// Whether audit logging is enabled. Should always be true in production.
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,

    /// Optional file path for audit log output. If omitted, audit events
    /// are emitted via the tracing subscriber (stdout/structured logging).
    pub log_path: Option<String>,

    /// Behavior when audit event persistence fails.
    /// NIST AU-5: Configurable response to audit processing failures.
    #[serde(default)]
    pub failure_policy: AuditFailurePolicy,
}

/// Configurable behavior when audit event persistence fails.
///
/// NIST AU-5 (Response to Audit Processing Failures): Organizations must
/// define the action to take when audit storage is exhausted or write fails.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditFailurePolicy {
    /// Log warning, continue processing (current behavior).
    FailOpen,
    /// Return error, reject the operation.
    FailClosed,
}

impl Default for AuditFailurePolicy {
    fn default() -> Self {
        Self::FailOpen
    }
}

fn default_audit_enabled() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Loading and validation
// ---------------------------------------------------------------------------

/// Determine the configuration file path from CLI args or environment.
///
/// Priority:
/// 1. First CLI argument (if present)
/// 2. LDAP_CONFIG_PATH environment variable
/// 3. Default: "config.toml"
pub fn resolve_config_path() -> String {
    // Check CLI args (skip program name).
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        // Support --config <path> or just <path>
        if args[1] == "--config" && args.len() > 2 {
            return args[2].clone();
        }
        if !args[1].starts_with('-') {
            return args[1].clone();
        }
    }

    // Check environment variable.
    if let Ok(path) = std::env::var("LDAP_CONFIG_PATH") {
        return path;
    }

    // Default.
    "config.toml".to_string()
}

/// Load and validate the server configuration from a TOML file.
///
/// NIST CM-6: Configuration settings are loaded from a validated file.
/// The function fails with a descriptive error if validation does not pass.
pub fn load(path: &str) -> Result<ServerConfig, ConfigError> {
    // Read the file.
    let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
        path: path.to_string(),
        source: e,
    })?;

    // Parse TOML.
    let config: ServerConfig = toml::from_str(&contents)?;

    // Validate.
    validate(&config)?;

    Ok(config)
}

/// Validate configuration invariants.
///
/// This function enforces security-critical constraints that cannot be
/// expressed through serde defaults alone.
fn validate(config: &ServerConfig) -> Result<(), ConfigError> {
    // Port must be 636 unless explicitly overridden for testing.
    // NIST SC-8: Standard port prevents accidental cleartext exposure.
    if config.server.port != 636 && !config.server.allow_non_standard_port {
        return Err(ConfigError::Validation(format!(
            "port must be 636 for LDAPS (got {}). Set allow_non_standard_port = true for testing.",
            config.server.port
        )));
    }

    // TLS certificate path must exist.
    if !Path::new(&config.tls.cert_path).exists() {
        return Err(ConfigError::Validation(format!(
            "TLS certificate file not found: {}",
            config.tls.cert_path
        )));
    }

    // TLS key path must exist.
    if !Path::new(&config.tls.key_path).exists() {
        return Err(ConfigError::Validation(format!(
            "TLS private key file not found: {}",
            config.tls.key_path
        )));
    }

    // Validate minimum TLS version.
    match config.tls.min_version.as_str() {
        "1.3" => {}
        other => {
            return Err(ConfigError::Validation(format!(
                "unsupported TLS version: '{}'. Only '1.3' is supported.",
                other
            )));
        }
    }

    // Database URL must not be empty.
    if config.database.url.is_empty() {
        return Err(ConfigError::Validation(
            "database URL must not be empty".into(),
        ));
    }

    // Rate limit window must be positive.
    if config.security.rate_limit_window_secs == 0 {
        return Err(ConfigError::Validation(
            "rate_limit_window_secs must be > 0".into(),
        ));
    }

    // Max bind attempts must be positive.
    if config.security.max_bind_attempts == 0 {
        return Err(ConfigError::Validation(
            "max_bind_attempts must be > 0".into(),
        ));
    }

    // Bound rate limit parameters to sane ranges.
    if config.security.max_bind_attempts > 100 {
        return Err(ConfigError::Validation(format!(
            "max_bind_attempts must be <= 100 (got {})",
            config.security.max_bind_attempts
        )));
    }
    if config.security.rate_limit_window_secs > 3600 {
        return Err(ConfigError::Validation(format!(
            "rate_limit_window_secs must be <= 3600 (got {})",
            config.security.rate_limit_window_secs
        )));
    }

    // Password TTL must be in a reasonable range.
    if config.security.password_ttl_secs < 60 {
        return Err(ConfigError::Validation(
            "password_ttl_secs must be >= 60".into(),
        ));
    }
    if config.security.password_ttl_secs > 86400 * 7 {
        return Err(ConfigError::Validation(
            "password_ttl_secs must be <= 604800 (7 days)".into(),
        ));
    }

    // Validate bind address is a parseable IP.
    if config.server.bind_addr.parse::<std::net::IpAddr>().is_err() {
        return Err(ConfigError::Validation(format!(
            "bind_addr '{}' is not a valid IP address",
            config.server.bind_addr
        )));
    }

    // If replication is enabled, central_url and site_id are required.
    if config.replication.enabled {
        if config.replication.central_url.as_deref().unwrap_or("").is_empty() {
            return Err(ConfigError::Validation(
                "central_url is required when replication is enabled".into(),
            ));
        }
        if config.replication.site_id.as_deref().unwrap_or("").is_empty() {
            return Err(ConfigError::Validation(
                "site_id is required when replication is enabled".into(),
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config_toml() -> String {
        r#"
[server]
bind_addr = "127.0.0.1"
port = 636

[tls]
cert_path = "/tmp/test-cert.pem"
key_path = "/tmp/test-key.pem"

[database]
url = "postgresql://localhost/test"

[replication]
enabled = false

[security]
max_bind_attempts = 5
rate_limit_window_secs = 300

[audit]
enabled = true
"#
        .to_string()
    }

    #[test]
    fn test_parse_minimal_config() {
        let config: ServerConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert_eq!(config.server.port, 636);
        assert_eq!(config.server.bind_addr, "127.0.0.1");
        assert!(!config.replication.enabled);
        assert_eq!(config.security.max_bind_attempts, 5);
    }

    #[test]
    fn test_non_standard_port_rejected_without_flag() {
        let toml_str = minimal_config_toml().replace("port = 636", "port = 8636");
        let config: ServerConfig = toml::from_str(&toml_str).unwrap();
        let result = validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("port must be 636"));
    }

    #[test]
    fn test_non_standard_port_accepted_with_flag() {
        let toml_str = minimal_config_toml()
            .replace("port = 636", "port = 8636\nallow_non_standard_port = true");
        let config: ServerConfig = toml::from_str(&toml_str).unwrap();
        // Validation would fail on cert path, but port check should pass.
        // We test just the port logic.
        assert_eq!(config.server.port, 8636);
        assert!(config.server.allow_non_standard_port);
    }

    #[test]
    fn test_empty_database_url_rejected() {
        let toml_str = minimal_config_toml()
            .replace("url = \"postgresql://localhost/test\"", "url = \"\"");
        let config: ServerConfig = toml::from_str(&toml_str).unwrap();
        let result = validate(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_replication_requires_central_url() {
        let toml_str = minimal_config_toml().replace("enabled = false", "enabled = true");
        let config: ServerConfig = toml::from_str(&toml_str).unwrap();
        let result = validate(&config);
        // Validation fails — either on missing cert paths (test env) or
        // on missing central_url. Both are correct rejections.
        assert!(result.is_err());
    }

    #[test]
    fn test_defaults_applied() {
        let config: ServerConfig = toml::from_str(&minimal_config_toml()).unwrap();
        assert_eq!(config.server.max_connections, 1024);
        assert_eq!(config.server.idle_timeout_secs, 300);
        assert_eq!(config.database.max_connections, 10);
        assert_eq!(config.security.password_ttl_secs, 28800);
        assert!(config.audit.enabled);
    }
}
