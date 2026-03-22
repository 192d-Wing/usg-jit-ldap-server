//! Admin HTTP endpoint for health checks and operational monitoring.
//!
//! Listens on a separate port (default 9090) and responds to GET /healthz
//! with a JSON health report.
//!
//! NIST SI-4: System monitoring — provides runtime health information
//! for operational monitoring and alerting systems.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Maximum admin requests per second (simple token bucket).
const ADMIN_MAX_RPS: u64 = 10;

/// Health status response.
#[derive(serde::Serialize)]
struct HealthResponse {
    status: &'static str,
    db_connected: bool,
    uptime_secs: u64,
}

/// Start the admin HTTP listener.
pub async fn start_admin_server(bind_addr: SocketAddr, pool: Arc<PgPool>, start_time: Instant) {
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => {
            tracing::info!(addr = %bind_addr, "admin health endpoint listening");
            l
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to bind admin endpoint");
            return;
        }
    };

    // Simple rate limiter: track request count per second window.
    let request_count = Arc::new(AtomicU64::new(0));
    let request_count_reset = request_count.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            request_count_reset.store(0, Ordering::Relaxed);
        }
    });

    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(error = %e, "admin accept error");
                continue;
            }
        };

        let pool = pool.clone();
        let start = start_time;
        let req_count = request_count.clone();

        tokio::spawn(async move {
            // Rate limit check.
            if req_count.fetch_add(1, Ordering::Relaxed) >= ADMIN_MAX_RPS {
                let response = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
                return;
            }
            let mut buf = [0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);

            // Only handle GET /healthz
            if request.starts_with("GET /healthz") {
                let db_ok = sqlx::query("SELECT 1").execute(pool.as_ref()).await.is_ok();

                let health = HealthResponse {
                    status: if db_ok { "ok" } else { "degraded" },
                    db_connected: db_ok,
                    uptime_secs: start.elapsed().as_secs(),
                };

                let body = serde_json::to_string(&health)
                    .unwrap_or_else(|_| r#"{"status":"error"}"#.to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else {
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
    }
}
