// SPDX-License-Identifier: Apache-2.0
//
// USG JIT LDAP Server — Entry Point
//
// This is the main entry point that wires together all subsystems into a
// running LDAPS server. It performs the following startup sequence:
//
// 1. Load and validate configuration (NIST CM-6)
// 2. Initialize tracing subscriber for structured logging
// 3. Connect to PostgreSQL and run migrations
// 4. Load TLS certificates — FAIL if unavailable (NIST SC-8, fail-closed)
// 5. Start replication puller if enabled (NIST CP-9)
// 6. Bind LDAPS listener on configured address:636
// 7. Accept TLS connections and spawn per-connection tasks
// 8. Handle graceful shutdown on SIGTERM/SIGINT
//
// NIST SP 800-53 Rev. 5:
// - CM-6 (Configuration Settings): All operational parameters loaded from
//   a validated configuration file.
// - SC-8 (Transmission Confidentiality): Server does not start without valid
//   TLS material. There is no cleartext LDAP code path.
// - SC-23 (Session Authenticity): One session per TLS connection.
// - AU-2 (Audit Events): Service lifecycle events are logged.

use usg_jit_ldap_server::admin;
use usg_jit_ldap_server::audit;
use usg_jit_ldap_server::auth;
use usg_jit_ldap_server::config;
use usg_jit_ldap_server::db;
use usg_jit_ldap_server::ldap;
use usg_jit_ldap_server::replication;
use usg_jit_ldap_server::tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use audit::AuditLogger;
use audit::events::AuditEvent;
use auth::rate_limit::{BindIpRateLimiter, RateLimiter, SearchRateLimiter};
use auth::{
    ConfigBrokerAuthorizer, DatabaseAuthenticator, DatabasePasswordStore, DatabaseSearchBackend,
};
use db::pool::DbPool;
use ldap::LdapHandler;
use ldap::codec::LdapCodec;
use ldap::session::LdapSession;
use replication::ReplicationConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Load configuration.
    // NIST CM-6: Configuration settings loaded from validated file.
    let config_path = config::resolve_config_path();

    // Initialize tracing early (before config validation) so we can log errors.
    // Step 2: Initialize tracing subscriber.
    init_tracing();

    tracing::info!("USG JIT LDAP Server starting");
    tracing::info!(config_path = %config_path, "loading configuration");

    let server_config = match config::load(&config_path) {
        Ok(c) => {
            tracing::info!(
                bind_addr = %c.server.bind_addr,
                port = c.server.port,
                replication_enabled = c.replication.enabled,
                "configuration loaded and validated"
            );
            c
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to load configuration — aborting");
            return Err(e.into());
        }
    };

    // Emit config-loaded audit event via tracing (DB not yet connected).
    let pre_audit = AuditLogger::tracing_only();
    pre_audit.log_sync(&AuditEvent::config_loaded(
        &config_path,
        &server_config.server.bind_addr,
        server_config.server.port,
        server_config.replication.enabled,
    ));

    // Step 3: Connect to PostgreSQL and run migrations.
    // NIST CM-6: Database URL must come from validated configuration only.
    // Environment variable fallback is intentionally removed to prevent
    // injection via DATABASE_URL in container/CI environments.
    let db_url = &server_config.database.url;
    if db_url.is_empty() {
        tracing::error!("database.url is not configured — aborting");
        return Err("database.url must be set in config file".into());
    }

    tracing::info!("connecting to PostgreSQL");
    let db_pool = match DbPool::connect(db_url, server_config.database.max_connections).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "failed to connect to database — aborting");
            return Err(e.into());
        }
    };

    // Run migrations.
    if let Err(e) = db_pool.run_migrations().await {
        tracing::error!(error = %e, "failed to run database migrations — aborting");
        return Err(e.into());
    }

    let pg_pool = Arc::new(db_pool.inner().clone());

    // Step 4: Load TLS certificates — FAIL if certs are missing or invalid.
    // NIST SC-8: Transmission confidentiality — server does not start without valid certs.
    // NIST SC-17: PKI certificates validated at startup.
    tracing::info!("loading TLS certificates");
    let tls_acceptor = match tls::build_tls_acceptor(&server_config.tls) {
        Ok(acceptor) => {
            tracing::info!("TLS acceptor built successfully — fail-closed enforcement active");
            acceptor
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "FATAL: TLS configuration failed — server cannot start without valid certificates"
            );
            tracing::error!("NIST SC-8 enforcement: refusing to start without TLS");
            return Err(e.into());
        }
    };

    // Spawn background certificate expiry monitor (checks every hour).
    // NIST SC-17: Continuous PKI certificate validity monitoring.
    tls::spawn_cert_expiry_monitor(server_config.tls.cert_path.clone(), 3600);

    // Create the audit logger (now with database backing).
    let audit_logger = AuditLogger::new(
        pg_pool.clone(),
        server_config.audit.enabled,
        server_config.audit.failure_policy,
    );

    // Step 5: Start replication puller if enabled.
    let _replication_handle = if server_config.replication.enabled {
        let repl_config = ReplicationConfig::from_settings(&server_config.replication);
        tracing::info!(
            site_id = %repl_config.site_id,
            pull_interval_secs = repl_config.pull_interval.as_secs(),
            "starting replication puller"
        );
        let (handle, health) = replication::puller::spawn_puller(repl_config, pg_pool.clone());
        Some((handle, health))
    } else {
        tracing::info!("replication is disabled (this is expected for the central hub)");
        None
    };

    // Spawn periodic cleanup task for audit queue and expired passwords.
    {
        let cleanup_pool = pg_pool.clone();
        let retention_days = server_config.audit.retention_days;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                // Clean forwarded audit events.
                match crate::db::runtime::cleanup_forwarded_audit_events(
                    &cleanup_pool,
                    retention_days,
                )
                .await
                {
                    Ok(n) if n > 0 => tracing::info!(deleted = n, "audit queue cleanup completed"),
                    Err(e) => tracing::warn!(error = %e, "audit queue cleanup failed"),
                    _ => {}
                }
                // Clean stale passwords.
                match crate::db::runtime::cleanup_stale_passwords(&cleanup_pool).await {
                    Ok(n) if n > 0 => {
                        tracing::info!(deleted = n, "stale password cleanup completed")
                    }
                    Err(e) => tracing::warn!(error = %e, "stale password cleanup failed"),
                    _ => {}
                }
            }
        });
        tracing::info!(
            retention_days = retention_days,
            "periodic cleanup task started (hourly)"
        );
    }

    // Step 5b: Start admin health endpoint if enabled.
    // NIST SI-4: System monitoring for operational awareness.
    let start_time = Instant::now();
    if server_config.admin.enabled {
        match format!(
            "{}:{}",
            server_config.admin.bind_addr, server_config.admin.port
        )
        .parse::<SocketAddr>()
        {
            Ok(admin_addr) => {
                let admin_pool = pg_pool.clone();
                tokio::spawn(async move {
                    admin::start_admin_server(admin_addr, admin_pool, start_time).await;
                });
                tracing::info!(
                    addr = %server_config.admin.bind_addr,
                    port = server_config.admin.port,
                    "admin health endpoint spawned"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    bind_addr = %server_config.admin.bind_addr,
                    port = server_config.admin.port,
                    "invalid admin bind address — skipping admin endpoint"
                );
            }
        }
    } else {
        tracing::info!("admin health endpoint disabled");
    }

    // Step 6: Bind LDAPS listener.
    let listen_addr: SocketAddr = format!(
        "{}:{}",
        server_config.server.bind_addr, server_config.server.port
    )
    .parse()
    .map_err(|e| {
        format!(
            "invalid bind address '{}:{}': {}",
            server_config.server.bind_addr, server_config.server.port, e
        )
    })?;

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        addr = %listen_addr,
        "LDAPS listener bound — accepting connections"
    );

    // Emit service-started audit event.
    audit_logger
        .log(AuditEvent::service_started(
            &server_config.server.bind_addr,
            server_config.server.port,
            &server_config.tls.min_version,
        ))
        .await;

    // Shared state for connection handlers.
    let rate_limiter = RateLimiter::new(
        pg_pool.clone(),
        server_config.security.max_bind_attempts,
        server_config.security.rate_limit_window_secs,
    );
    let bind_ip_rate_limiter = BindIpRateLimiter::new(
        pg_pool.clone(),
        server_config.security.max_bind_ip_attempts,
        server_config.security.bind_ip_rate_window_secs,
    );
    let search_rate_limiter = SearchRateLimiter::new(
        pg_pool.clone(),
        server_config.security.max_searches_per_minute,
        server_config.security.search_rate_window_secs,
    );
    let broker_authorizer = Arc::new(ConfigBrokerAuthorizer::new(
        server_config.security.broker_dns.clone(),
    ));
    let conn_semaphore = Arc::new(Semaphore::new(server_config.server.max_connections));
    let password_ttl = server_config.security.password_ttl_secs;
    let idle_timeout_secs = server_config.server.idle_timeout_secs;
    let max_session_lifetime_secs = server_config.server.max_session_lifetime_secs;

    // Step 7 & 8: Accept connections with graceful shutdown.
    // NIST SC-23: Each TLS connection gets exactly one LDAP session.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcp_stream, peer_addr)) => {
                        // NIST SC-5: Connection limit enforcement.
                        let Ok(permit) = conn_semaphore.clone().try_acquire_owned() else {
                            tracing::warn!(
                                peer = %peer_addr,
                                max = server_config.server.max_connections,
                                "connection rejected: max connections reached"
                            );
                            drop(tcp_stream);
                            continue;
                        };

                        tracing::debug!(peer = %peer_addr, "accepted TCP connection");

                        // Clone shared resources for the connection task.
                        let tls_acceptor = tls_acceptor.clone();
                        let pool = pg_pool.clone();
                        let rate_limiter = rate_limiter.clone();
                        let bind_ip_rate_limiter = bind_ip_rate_limiter.clone();
                        let search_rate_limiter = search_rate_limiter.clone();
                        let audit = audit_logger.clone();
                        let broker_auth = broker_authorizer.clone();
                        let idle_timeout = idle_timeout_secs;
                        let max_lifetime = max_session_lifetime_secs;

                        tokio::spawn(async move {
                            // Perform TLS handshake.
                            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                Ok(stream) => stream,
                                Err(e) => {
                                    tracing::warn!(
                                        peer = %peer_addr,
                                        error = %e,
                                        "TLS handshake failed"
                                    );
                                    audit.log(AuditEvent::TlsError {
                                        timestamp: chrono::Utc::now(),
                                        source_addr: peer_addr.to_string(),
                                        error_detail: "TLS handshake failed".to_string(),
                                    }).await;
                                    drop(permit);
                                    return;
                                }
                            };

                            // Extract client certificate DN for audit attribution (NIST IA-3).
                            let client_cert_dn: Option<String> = tls_stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .and_then(|certs| certs.first())
                                .and_then(|cert| {
                                    x509_parser::parse_x509_certificate(cert.as_ref())
                                        .ok()
                                        .map(|(_, parsed)| parsed.subject().to_string())
                                });

                            tracing::info!(
                                peer = %peer_addr,
                                client_cert_dn = ?client_cert_dn,
                                "TLS handshake complete (mTLS verified)"
                            );
                            audit.log(AuditEvent::ConnectionOpened {
                                timestamp: chrono::Utc::now(),
                                source_addr: peer_addr.to_string(),
                                client_cert_dn: client_cert_dn.clone(),
                            }).await;

                            // Handle the LDAP connection.
                            handle_connection(
                                tls_stream,
                                peer_addr,
                                pool,
                                rate_limiter,
                                bind_ip_rate_limiter,
                                search_rate_limiter,
                                audit,
                                broker_auth,
                                password_ttl,
                                idle_timeout,
                                max_lifetime,
                                client_cert_dn,
                            ).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to accept TCP connection");
                    }
                }
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received — stopping listener");
                break;
            }
        }
    }

    // Graceful shutdown.
    tracing::info!("shutting down gracefully");
    audit_logger
        .log(AuditEvent::service_stopped("shutdown signal received"))
        .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Handle a single LDAP connection over TLS.
///
/// NIST SC-23: Session authenticity — one LDAP session per TLS connection.
/// The session state machine (Connected -> Bound -> Closed) is maintained
/// entirely on the server side. The client cannot forge session state.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    pool: Arc<sqlx::PgPool>,
    rate_limiter: RateLimiter,
    bind_ip_rate_limiter: BindIpRateLimiter,
    search_rate_limiter: SearchRateLimiter,
    audit: AuditLogger,
    broker_authorizer: Arc<ConfigBrokerAuthorizer>,
    password_ttl: u64,
    idle_timeout_secs: u64,
    max_session_lifetime_secs: u64,
    client_cert_dn: Option<String>,
) {
    let connection_start = Instant::now();

    // Build per-connection concrete implementations of the protocol traits.
    // NIST IA-2: The authenticator is the identification and authentication
    // enforcement point for this connection.
    let authenticator = DatabaseAuthenticator::new(
        pool.clone(),
        rate_limiter,
        bind_ip_rate_limiter,
        audit.clone(),
        peer_addr,
        client_cert_dn.clone(),
    );
    let search_backend = DatabaseSearchBackend::new(pool.clone(), search_rate_limiter, peer_addr);
    let password_store = DatabasePasswordStore::new(pool.clone(), password_ttl);

    // Construct the LdapHandler with concrete backends.
    // This is where the protocol traits meet their implementations.
    let handler = LdapHandler::new(
        authenticator,
        search_backend,
        password_store,
        ConfigBrokerAuthorizer::new(broker_authorizer.authorized_dns_ref().to_vec()),
        audit.clone(),
    );

    // Create the session state machine for this connection.
    let mut session = LdapSession::new(peer_addr, client_cert_dn);

    // Create the BER codec for framing.
    let codec = LdapCodec::new();

    // Split the TLS stream for reading and writing.
    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    // Read buffer for incoming data.
    let mut read_buf = Vec::with_capacity(8192);
    let mut temp_buf = [0u8; 4096];

    let idle_timeout = tokio::time::Duration::from_secs(idle_timeout_secs);
    let max_lifetime = tokio::time::Duration::from_secs(max_session_lifetime_secs);

    loop {
        // NIST SC-10: Enforce absolute session lifetime regardless of activity.
        if connection_start.elapsed() >= max_lifetime {
            tracing::info!(
                peer = %peer_addr,
                lifetime_secs = max_session_lifetime_secs,
                "absolute session lifetime exceeded — closing connection"
            );
            break;
        }

        // Read data with idle timeout.
        let read_result = tokio::time::timeout(idle_timeout, reader.read(&mut temp_buf)).await;

        match read_result {
            Ok(Ok(0)) => {
                // Connection closed by client.
                tracing::debug!(peer = %peer_addr, "client closed connection");
                break;
            }
            Ok(Ok(n)) => {
                read_buf.extend_from_slice(&temp_buf[..n]);
                // NIST SI-10: Reject if accumulated buffer exceeds max message size.
                if read_buf.len() > ldap::codec::MAX_MESSAGE_SIZE + 1024 {
                    tracing::warn!(
                        peer = %peer_addr,
                        buf_size = read_buf.len(),
                        "read buffer exceeds maximum — closing connection"
                    );
                    break;
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(peer = %peer_addr, error = %e, "read error");
                break;
            }
            Err(_) => {
                // Idle timeout.
                tracing::info!(
                    peer = %peer_addr,
                    timeout_secs = idle_timeout_secs,
                    "connection idle timeout — closing"
                );
                break;
            }
        }

        // Process all complete messages in the buffer.
        loop {
            match codec.decode_frame(&read_buf) {
                Ok(Some((msg, consumed))) => {
                    // Remove consumed bytes from the buffer.
                    read_buf.drain(..consumed);

                    tracing::debug!(
                        peer = %peer_addr,
                        message_id = msg.message_id,
                        "received LDAP message"
                    );

                    // Process the message through the handler.
                    let responses = handler.process_message(&mut session, msg).await;

                    // Write all response messages back to the client.
                    for response in responses {
                        match codec.encode_frame(&response) {
                            Ok(bytes) => {
                                if let Err(e) = writer.write_all(&bytes).await {
                                    tracing::warn!(
                                        peer = %peer_addr,
                                        error = %e,
                                        "write error — closing connection"
                                    );
                                    // Ensure session is closed on write error.
                                    session.transition_to_closed();
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    peer = %peer_addr,
                                    error = %e,
                                    "failed to encode response"
                                );
                            }
                        }
                    }

                    // If session is closed (Unbind or error), stop processing.
                    if matches!(session.state(), ldap::session::SessionState::Closed) {
                        break;
                    }
                }
                Ok(None) => {
                    // Need more data — break inner loop, read more.
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %peer_addr,
                        error = %e,
                        "codec decode error — closing connection"
                    );
                    session.transition_to_closed();
                    break;
                }
            }
        }

        // If session is closed, exit the outer loop too.
        if matches!(session.state(), ldap::session::SessionState::Closed) {
            break;
        }
    }

    // Emit connection-closed audit event.
    let duration = connection_start.elapsed();
    audit
        .log(AuditEvent::ConnectionClosed {
            timestamp: chrono::Utc::now(),
            source_addr: peer_addr.to_string(),
            messages_processed: session.message_counter(),
            duration_secs: duration.as_secs_f64(),
        })
        .await;

    tracing::info!(
        peer = %peer_addr,
        messages = session.message_counter(),
        duration_secs = duration.as_secs_f64(),
        "connection closed"
    );
}

// ---------------------------------------------------------------------------
// Tracing initialization
// ---------------------------------------------------------------------------

/// Initialize the tracing subscriber with structured JSON output and
/// environment-based filtering.
///
/// NIST AU-3: Structured logging ensures audit records contain the required
/// contextual fields (timestamps, source, outcome).
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(false)
        .with_line_number(false)
        .init();
}
