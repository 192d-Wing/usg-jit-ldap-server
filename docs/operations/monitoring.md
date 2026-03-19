# Monitoring

This document describes the key metrics, alerting thresholds, log queries, and dashboard guidance for operating the USG JIT LDAP Server.

---

## Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ldap_bind_total` | Counter | Total BIND attempts (label: `result=success\|failure`) |
| `ldap_bind_duration_seconds` | Histogram | Time to process a BIND operation |
| `ldap_search_total` | Counter | Total SEARCH operations |
| `ldap_search_duration_seconds` | Histogram | Time to process a SEARCH operation |
| `ldap_connections_active` | Gauge | Current number of open client connections |
| `ldap_connections_total` | Counter | Total connections accepted since startup |
| `auth_failures_total` | Counter | Failed authentication attempts (label: `source_ip`) |
| `auth_rate_limited_total` | Counter | Requests rejected by rate limiting |
| `jit_credentials_provisioned_total` | Counter | JIT credentials created |
| `jit_credentials_expired_total` | Counter | JIT credentials that have expired |
| `replication_last_success_timestamp` | Gauge | Unix timestamp of last successful replication pull |
| `replication_last_sequence` | Gauge | Most recent sequence number from central |
| `replication_pull_duration_seconds` | Histogram | Time for each replication pull |
| `replication_consecutive_failures` | Gauge | Number of consecutive failed replication pulls |
| `audit_events_total` | Counter | Total audit events written |
| `audit_queue_depth` | Gauge | Number of audit events pending write |
| `audit_write_failures_total` | Counter | Failed audit write attempts |
| `db_pool_connections_active` | Gauge | Active database connections in the pool |
| `db_pool_connections_idle` | Gauge | Idle database connections in the pool |
| `db_pool_acquire_duration_seconds` | Histogram | Time to acquire a connection from the pool |

---

## Alerting Thresholds

### Critical (page immediately)

| Condition | Threshold | Rationale |
|-----------|-----------|-----------|
| Auth failure rate | > 50 failures/min sustained for 5 min | Possible brute-force attack |
| Audit write failures | Any (`audit_write_failures_total` increases) | Audit integrity at risk |
| TLS certificate expiry | < 7 days until expiry | Service will become unavailable |
| Database connection pool exhausted | `db_pool_connections_active` = `max_connections` for > 1 min | All queries will block |
| Replication stale | `replication_last_success_timestamp` > `stale_threshold_secs` | Identity data may be outdated |

### Warning (investigate during business hours)

| Condition | Threshold | Rationale |
|-----------|-----------|-----------|
| Auth failure rate | > 20 failures/min sustained for 10 min | Elevated failure rate |
| TLS certificate expiry | < 30 days until expiry | Plan rotation |
| Replication pull failures | `replication_consecutive_failures` > 3 | WAN or central service issue |
| Connection count | > 80% of `max_connections` | Approaching capacity |
| Audit queue depth | > 1000 events pending | Write backpressure building |
| Database acquire latency | p99 > 500ms | Pool may be undersized |

---

## Log Queries for Common Investigations

All examples assume the audit log is in JSON Lines format at `/var/log/ldap-server/audit.jsonl`.

### Failed BINDs by Source IP (last hour)

```bash
grep '"event":"bind_failure"' /var/log/ldap-server/audit.jsonl | \
  grep "$(date -u +%Y-%m-%dT%H)" | \
  jq -r '.source_ip' | sort | uniq -c | sort -rn | head -20
```

### Successful BINDs for a Specific DN

```bash
grep '"event":"bind_success"' /var/log/ldap-server/audit.jsonl | \
  grep '"bind_dn":"cn=specific-user' | \
  jq -r '[.timestamp, .source_ip] | @tsv'
```

### All Activity from a Specific IP

```bash
grep '"source_ip":"10.0.0.50"' /var/log/ldap-server/audit.jsonl | \
  jq -r '[.timestamp, .event, .bind_dn] | @tsv' | sort
```

### JIT Credential Provisioning Events

```bash
grep '"event":"jit_credential_provisioned"' /var/log/ldap-server/audit.jsonl | \
  jq -r '[.timestamp, .bind_dn, .broker] | @tsv' | tail -20
```

### Replication Events (successes and failures)

```bash
grep '"event":"replication_' /var/log/ldap-server/audit.jsonl | \
  jq -r '[.timestamp, .event, .sequence, .records_pulled] | @tsv' | tail -20
```

### Rate-Limited Requests

```bash
grep '"event":"rate_limited"' /var/log/ldap-server/audit.jsonl | \
  jq -r '[.timestamp, .source_ip, .bind_dn] | @tsv' | sort | uniq -c | sort -rn
```

---

## Dashboard Guidance

### Suggested Grafana Panels

#### Overview Row

1. **BIND Rate** — `rate(ldap_bind_total[5m])` split by `result`. Shows real-time authentication activity.
2. **Active Connections** — `ldap_connections_active`. Gauge showing current load.
3. **Auth Failure Rate** — `rate(auth_failures_total[5m])`. Line chart with alert threshold overlay.

#### Replication Row

4. **Replication Lag** — `time() - replication_last_success_timestamp`. Single-stat panel with thresholds (green < 300s, yellow < 900s, red > 900s).
5. **Replication Sequence** — `replication_last_sequence`. Line chart to visualize steady progression.
6. **Pull Duration** — `replication_pull_duration_seconds` histogram quantiles (p50, p95, p99).

#### Database Row

7. **Pool Utilization** — `db_pool_connections_active / max_connections`. Gauge with 80% warning threshold.
8. **Acquire Latency** — `db_pool_acquire_duration_seconds` quantiles. Line chart.
9. **Query Errors** — Rate of database-related error log entries.

#### Audit Row

10. **Audit Queue Depth** — `audit_queue_depth`. Line chart with 1000-event warning line.
11. **Audit Write Rate** — `rate(audit_events_total[5m])`. Shows audit system throughput.
12. **Write Failures** — `audit_write_failures_total`. Counter that should always be 0.

#### Security Row

13. **Top Failed BIND Sources** — Table panel using log query or `topk(10, auth_failures_total)`.
14. **Rate-Limited Requests** — `rate(auth_rate_limited_total[5m])`. Spikes indicate active attacks or misconfigurations.
15. **JIT Credential Lifecycle** — Provisioned vs. expired credentials over time.

### Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'ldap-server'
    scrape_interval: 15s
    static_configs:
      - targets: ['ldap-server-host:9090']  # Metrics port (when implemented)
    metrics_path: /metrics
```

---

## Health Check Endpoint (Planned)

When implemented, the server will expose a health check endpoint for load balancers and monitoring systems.

### Proposed Design

**Endpoint:** `GET /healthz` on the metrics port.

**Response:**

```json
{
  "status": "healthy",
  "checks": {
    "database": { "status": "up", "latency_ms": 2 },
    "replication": { "status": "up", "last_success_secs_ago": 45 },
    "tls_certificate": { "status": "ok", "expires_in_days": 142 },
    "audit": { "status": "ok", "queue_depth": 3 }
  }
}
```

**Status values:**
- `healthy` — all checks pass.
- `degraded` — one or more checks are in a warning state (e.g. replication stale, certificate expiring soon).
- `unhealthy` — a critical check has failed (e.g. database unreachable, audit write failure).

**HTTP status codes:**
- `200` — healthy or degraded.
- `503` — unhealthy (signals load balancers to stop routing traffic).
