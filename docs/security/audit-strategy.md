# Audit Logging Strategy: USG JIT LDAP Server

This document defines the audit logging strategy for the USG JIT LDAP Server,
covering event selection, record format, storage, forwarding, retention, tamper
detection, and NIST AU family compliance.

## Auditable Events (AU-2)

The following events are logged. This is an exhaustive list; any security-relevant
operation that does not appear here is a gap that must be addressed.

### Authentication Events

| Event Type | Trigger | Severity | Fields |
|---|---|---|---|
| `bind_attempt` (success) | Successful LDAP Simple Bind | INFO | timestamp, source_addr, dn, outcome=Success |
| `bind_attempt` (invalid_credentials) | Failed Bind — wrong password | WARN | timestamp, source_addr, dn, outcome=InvalidCredentials |
| `bind_attempt` (invalid_credentials) | Failed Bind — user not found, account disabled, or wrong password | WARN | timestamp, source_addr, dn, outcome=InvalidCredentials |
| `bind_attempt` (account_locked) | Failed Bind — rate limit lockout | WARN | timestamp, source_addr, dn, outcome=AccountLocked |
| `bind_attempt` (rate_limited) | Failed Bind — per-DN or per-IP rate limit exceeded | WARN | timestamp, source_addr, dn, outcome=RateLimited |
| `bind_attempt` (internal_error) | Failed Bind — internal error | ERROR | timestamp, source_addr, dn, outcome=InternalError |

### Directory Operation Events

| Event Type | Trigger | Severity | Fields |
|---|---|---|---|
| `search_request` | Search operation initiated | INFO | timestamp, source_addr, bound_dn, base_dn, scope, filter_summary |
| `search_complete` | Search operation completed | INFO | timestamp, source_addr, bound_dn, base_dn, entries_returned, result_code |

### Credential Management Events

| Event Type | Trigger | Severity | Fields |
|---|---|---|---|
| `password_modify` (success) | JIT Broker issued a credential | INFO | timestamp, source_addr, broker_dn, target_dn, success=true |
| `password_modify` (failure) | Password Modify operation failed | WARN | timestamp, source_addr, broker_dn, target_dn, success=false, failure_reason |

### Rate Limiting Events

| Event Type | Trigger | Severity | Fields |
|---|---|---|---|
| `rate_limit_triggered` | DN exceeded bind attempt threshold | WARN | timestamp, source_addr, dn, attempt_count, window_secs |

### Connection Lifecycle Events

| Event Type | Trigger | Severity | Fields |
|---|---|---|---|
| `connection_opened` | TLS handshake completed | INFO | timestamp, source_addr |
| `connection_closed` | Connection terminated | INFO | timestamp, source_addr, messages_processed, duration_secs |
| `tls_error` | TLS handshake or connection error | WARN | timestamp, source_addr, error_detail (sanitized — no internal details) |

### Service Lifecycle Events

| Event Type | Trigger | Severity | Fields |
|---|---|---|---|
| `config_loaded` | Configuration file parsed and validated | INFO | timestamp, config_path, bind_addr, port, replication_enabled |
| `service_started` | LDAPS listener bound and accepting | INFO | timestamp, bind_addr, port, tls_min_version |
| `service_stopped` | Service shutting down | INFO | timestamp, reason |

### Replication Events (Planned)

| Event Type | Trigger | Severity | Fields |
|---|---|---|---|
| `replication_pull_success` | Replication pull completed | INFO | timestamp, site_id, sequence_number, entries_synced |
| `replication_pull_failure` | Replication pull failed | WARN | timestamp, site_id, error_detail, consecutive_failures |
| `replication_stale` | Data age exceeds staleness threshold | WARN | timestamp, site_id, last_sync_age_secs, threshold_secs |
| `replication_recovered` | Replication resumed after failure | INFO | timestamp, site_id, downtime_secs |

## Audit Record Format (AU-3)

All audit records are structured JSON objects. The format is designed for machine
parsing (SIEM ingestion) while remaining human-readable for manual review.

### Common Fields

Every audit record includes these fields:

```json
{
  "event_type": "bind_attempt",
  "details": {
    "timestamp": "2026-03-19T14:32:01.042Z",
    "source_addr": "10.42.1.15:52341",
    "dn": "cn=jdoe,ou=users,dc=example,dc=gov",
    "outcome": { "status": "Success" }
  }
}
```

| Field | Description | AU-3 Requirement |
|---|---|---|
| `event_type` | Discriminator for the event category | What type of event |
| `timestamp` | UTC ISO 8601 timestamp with millisecond precision | When the event occurred |
| `source_addr` | Client IP address and port | Where the event originated |
| `dn` / `bound_dn` / `broker_dn` | Distinguished Name of the subject | Who caused the event |
| `outcome` / `success` / `result_code` | Result of the operation | Whether it succeeded or failed |

### Content Requirements per AU-3

Each audit record answers the following questions:

1. **What** happened — `event_type` field
2. **When** it happened — `timestamp` field (UTC, ISO 8601)
3. **Where** it originated — `source_addr` field (client IP:port)
4. **Who** caused it — `dn`, `bound_dn`, or `broker_dn` field
5. **What was the outcome** — `outcome`, `success`, or `result_code` field

### What Is Explicitly Excluded

The following are NEVER included in audit records:
- Plaintext passwords
- Password hashes
- TLS private key material
- Session encryption keys
- Internal stack traces (replaced with sanitized error categories)

## Timestamp Handling (AU-8)

### Clock Source

All timestamps are generated using `chrono::Utc::now()`, which reads the system
clock. Timestamps are in UTC to avoid timezone ambiguity across 184 geographically
distributed sites.

### Format

ISO 8601 with timezone designator: `2026-03-19T14:32:01.042Z`

Millisecond precision is sufficient for ordering events within a single site. For
cross-site correlation, NTP synchronization is required (AU-8(1)).

### NTP Dependency

**Operator Responsibility:** Each site MUST run NTP or an equivalent time
synchronization service. The LDAP server does not implement or verify time
synchronization itself. Clock skew exceeding 1 second between the LDAP server and
the SIEM may cause event ordering anomalies during forensic analysis.

### Monotonic Ordering

Within a single LDAP server process, events are emitted in causal order (the audit
call occurs in the operation handler before the response is sent). The database
`runtime.audit_queue.id` column (BIGSERIAL) provides a monotonic sequence within
each site for gap detection.

## Storage Architecture

### Tier 1: In-Process Structured Logging

Audit events are emitted via the `tracing` framework as structured JSON log lines.
This provides immediate visibility for operators monitoring the service output.

**Destination:** stdout (captured by the process supervisor or container runtime)

**Latency:** Synchronous with the operation handler — the event is emitted before
the LDAP response is sent.

**Durability:** None — log lines are ephemeral unless captured by the supervisor.

### Tier 2: Database Persistence (runtime.audit_queue)

Audit events are persisted to the `runtime.audit_queue` table in the local
PostgreSQL database. This provides durable storage that survives process restarts.

**Schema:**
```sql
runtime.audit_queue (
    id           BIGSERIAL PRIMARY KEY,
    event_type   VARCHAR(128) NOT NULL,
    event_data   JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    forwarded    BOOLEAN NOT NULL DEFAULT FALSE,
    forwarded_at TIMESTAMPTZ
)
```

**Durability:** PostgreSQL WAL guarantees (fsync-durable within the site).

**Access Control:**
- LDAP service role: INSERT only (append-only from the service perspective)
- No DELETE permission for the LDAP service role
- A dedicated maintenance role handles retention/cleanup

### Tier 3: Central SIEM (Forwarding)

Audit events are forwarded from `runtime.audit_queue` to a central SIEM for
long-term storage, cross-site correlation, and alerting. The forwarding process
marks events as `forwarded = TRUE` after successful delivery.

## Forwarding Strategy

### Mechanism

A dedicated forwarder process (or sidecar) reads un-forwarded events from
`runtime.audit_queue` and delivers them to the central SIEM. The forwarder is
a separate process from the LDAP server to avoid coupling LDAP availability
to SIEM availability.

### Delivery Semantics

**At-least-once delivery:** The forwarder reads a batch of un-forwarded events,
delivers them to the SIEM, and then marks them as forwarded. If the forwarder
crashes between delivery and marking, events may be delivered twice. The SIEM
must handle deduplication (using `id` + `site_id` as a unique key).

### Failure Handling

If the SIEM is unreachable:
1. Events continue to accumulate in `runtime.audit_queue`.
2. The forwarder retries with exponential backoff.
3. If the queue exceeds a configurable size threshold, an alert is raised.
4. The LDAP server continues operating — audit logging does not block service
   availability (fail-open audit, fail-closed service).

### Batching

The forwarder reads events in configurable batch sizes (recommended: 100-500)
to balance latency and throughput. Each batch is delivered as a single request
to the SIEM API.

## Retention Policy Recommendations

### Local Retention (runtime.audit_queue)

| Data Category | Recommended Retention | Rationale |
|---|---|---|
| Forwarded events | 7 days after forwarding | Buffer for re-delivery if SIEM data is lost |
| Un-forwarded events | 30 days | Maximum local storage before alerting |
| Rate limit state | 24 hours (sliding window) | Operational; no long-term forensic value |
| Bind events | 90 days | Local forensic analysis capability |

### Central SIEM Retention

| Data Category | Recommended Retention | Rationale |
|---|---|---|
| All audit events | 1 year minimum | NIST AU-11, FISMA Moderate baseline |
| Security incidents | 3 years | Investigation and legal hold requirements |
| Compliance reports | 6 years | Federal records retention schedule |

### Cleanup Process

A scheduled maintenance job (cron or pg_cron) should:
1. DELETE forwarded events older than the local retention period
2. Alert on un-forwarded events older than 24 hours (forwarding failure indicator)
3. VACUUM the audit_queue table after bulk deletions

## Tamper Detection Considerations

### Database-Level Protections

- The LDAP service role has INSERT-only access to `runtime.audit_queue` — it cannot
  UPDATE or DELETE existing records.
- The `id` column (BIGSERIAL) provides a monotonic sequence; gaps in the sequence
  indicate deletion or transaction rollback.
- The `created_at` column is set by the database (`DEFAULT now()`), not by the
  application, preventing timestamp manipulation.

### Forwarding-Level Protections

- Once events are forwarded to the central SIEM, they are beyond the reach of a
  compromised site administrator.
- The SIEM should validate that the `id` sequence from each site is monotonically
  increasing; gaps indicate potential tampering.
- Cross-site correlation (e.g., replication events should appear in both the hub
  and the site's logs) provides additional integrity verification.

### Recommendations for Enhanced Tamper Detection

1. **Hash chain:** Each audit record could include a SHA-256 hash of the previous
   record, creating a blockchain-like integrity chain. This is not currently
   implemented but could be added in Phase 4.

2. **Write-once storage:** Forward audit events to a WORM (Write Once Read Many)
   storage backend at the SIEM layer.

3. **Signed events:** The LDAP server could sign each audit event with an
   HMAC-SHA256 using a key not stored in the database. This prevents tampering
   even by a database administrator.

## Log Review and Alerting Guidance (AU-6)

### Automated Alerts (SIEM Rules)

| Alert Name | Condition | Severity | Response |
|---|---|---|---|
| Brute Force Detected | >10 `bind_attempt` failures for same DN in 5 min | HIGH | Investigate source IP; consider IP block |
| Credential Spray | >50 `bind_attempt` failures from same IP across different DNs in 10 min | HIGH | Block source IP; investigate for compromise |
| Rate Limit Storm | >20 `rate_limit_triggered` events in 5 min | MEDIUM | Review source IPs; verify rate limit config |
| Unusual Search Volume | >100 `search_complete` from same DN in 10 min | MEDIUM | Review search patterns; verify authorized use |
| Audit Forwarding Lag | Un-forwarded events older than 1 hour | HIGH | Investigate forwarder health; check SIEM connectivity |
| Replication Stale | `replication_stale` event | HIGH | Investigate WAN connectivity; check hub health |
| Service Restart | `service_started` event after unexpected `service_stopped` | MEDIUM | Review shutdown reason; check for crash |
| TLS Error Spike | >5 `tls_error` events from same IP in 1 min | MEDIUM | Investigate client; possible protocol probe |
| Unauthorized Broker | `password_modify` from DN not in `broker_dns` list | CRITICAL | Immediate investigation; possible compromise |

### Manual Review Schedule

| Review Activity | Frequency | Reviewer | Focus |
|---|---|---|---|
| Failed Bind trend analysis | Daily | SOC analyst | Credential attack patterns |
| Search pattern review | Weekly | Security engineer | Data exfiltration indicators |
| Replication health review | Daily | Site operations | Sync lag and failure rates |
| Audit completeness check | Weekly | Compliance officer | Gap detection in event sequence |
| Broker issuance review | Weekly | IAM team | Unusual issuance patterns |
| Full audit log review | Monthly | Security lead | Systemic issues, policy violations |

## NIST AU Family Mapping

| Control | Title | Implementation | Status |
|---|---|---|---|
| AU-2 | Event Logging | `AuditEvent` enum defines 11+ event types covering all security-relevant operations. Event selection is comprehensive and documented in this strategy. | Implemented |
| AU-3 | Content of Audit Records | Each event includes timestamp (UTC), source IP, subject DN, event type, and outcome. JSON serialization preserves all fields. | Implemented |
| AU-3(1) | Additional Audit Information | Search events include base DN, scope, filter summary, and result count. Bind events include outcome classification. | Implemented |
| AU-4 | Audit Log Storage Capacity | `runtime.audit_queue` with configurable retention. Local PostgreSQL storage with size monitoring. | Implemented |
| AU-5 | Response to Audit Processing Failures | Audit logging failure does not block LDAP operations (fail-open audit). A metric is incremented and an alert is triggered on audit failures. | Implemented |
| AU-5(1) | Storage Capacity Warning | Recommended: monitor `runtime.audit_queue` row count and disk usage; alert at configurable threshold. | Planned |
| AU-6 | Audit Record Review, Analysis, Reporting | Structured JSON format enables automated SIEM analysis. Alert rules and review schedules defined in this document. | Implemented (format); Planned (SIEM rules) |
| AU-7 | Audit Record Reduction and Report Generation | JSONB storage supports SQL-based ad-hoc queries. SIEM provides dashboards and reports. | Planned (SIEM integration) |
| AU-8 | Time Stamps | All events use `chrono::Utc::now()` for UTC timestamps with millisecond precision. ISO 8601 format. | Implemented |
| AU-8(1) | Synchronization with Authoritative Time Source | NTP synchronization is an operator responsibility documented in operational guidance. | Operational (not in application code) |
| AU-9 | Protection of Audit Information | LDAP service role has INSERT-only access to audit_queue. No DELETE permission. Forwarding to central SIEM removes events from local admin's exclusive control. | Implemented (DB); Planned (SIEM forwarding) |
| AU-11 | Audit Record Retention | Local retention: 7-30 days (configurable). Central SIEM: 1 year minimum recommended. | Planned (retention automation) |
| AU-12 | Audit Record Generation | Audit events emitted from every operation handler before response is sent. `AuditLogger` provides both tracing and database persistence. | Implemented |
| AU-12(1) | System-Wide Audit Trail | Events from all 184 sites forwarded to central SIEM. Site ID included in forwarded events for correlation. | Planned (SIEM integration) |
