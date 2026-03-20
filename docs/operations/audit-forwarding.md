# Audit Queue Forwarding

This document describes the contract for forwarding audit events from the
site-local `runtime.audit_queue` table to an external SIEM or log aggregator.

NIST SP 800-53 Rev. 5 controls:

- **AU-6** (Audit Review, Analysis, and Reporting): events must reach a central
  system where security analysts can review them.
- **AU-9** (Protection of Audit Information): the queue is append-only from the
  application side; connectors must not DELETE unflagged rows.
- **AU-5** (Response to Audit Processing Failures): if forwarding fails, events
  remain in the queue and are retried on the next poll cycle.

---

## 1. The `runtime.audit_queue` Table

Every security-relevant action in the LDAP server is written to the audit queue
as a durable row before the operation is acknowledged to the client (fail-closed
semantics).

### Schema

| Column         | Type           | Description                                      |
|----------------|----------------|--------------------------------------------------|
| `id`           | `BIGSERIAL PK` | Monotonically increasing event identifier.       |
| `event_type`   | `VARCHAR(128)` | Machine-readable event name (see section 7).     |
| `event_data`   | `JSONB`        | Full structured event payload.                   |
| `created_at`   | `TIMESTAMPTZ`  | When the event was inserted (server clock).      |
| `forwarded`    | `BOOLEAN`      | `FALSE` until a connector marks it forwarded.    |
| `forwarded_at` | `TIMESTAMPTZ`  | Timestamp when the connector marked it done.     |

The partial index `idx_audit_queue_forwarded_created` covers
`(forwarded, created_at) WHERE forwarded = FALSE`, making the polling query
efficient even with millions of historical rows.

---

## 2. Polling for Unforwarded Events

A SIEM connector polls the queue by selecting the oldest unforwarded events in
creation order:

```sql
SELECT id, event_type, event_data, created_at
FROM runtime.audit_queue
WHERE forwarded = FALSE
ORDER BY created_at ASC
LIMIT 100;
```

**Design notes:**

- `ORDER BY created_at ASC` ensures events reach the SIEM in causal order.
- `LIMIT 100` (adjustable) keeps each batch manageable and avoids long-running
  transactions.
- The partial index makes this query an index-only scan when `forwarded = FALSE`
  rows are a small fraction of the table.

---

## 3. Marking Events as Forwarded

After the connector has durably delivered a batch to the SIEM, it marks those
rows as forwarded in a single statement:

```sql
UPDATE runtime.audit_queue
SET forwarded = TRUE,
    forwarded_at = now()
WHERE id = ANY($1);
```

`$1` is an array of `BIGINT` IDs from the batch. This is intentionally a
separate statement from the SELECT so that a crash between poll and mark results
in re-delivery (see section 5).

---

## 4. Retention and Cleanup

Forwarded events are retained for a configurable period (default: 90 days) to
support forensic look-back. The background cleanup job removes them:

```sql
DELETE FROM runtime.audit_queue
WHERE forwarded = TRUE
  AND forwarded_at < now() - make_interval(days => $1::int);
```

This cleanup runs as part of the server's periodic maintenance task (the same
job that purges expired ephemeral passwords and stale bind events). The
retention period is configured via the `audit.retention_days` setting.

**Never delete rows where `forwarded = FALSE`.** Those events have not yet
reached the SIEM and must remain in the queue until successfully delivered.

---

## 5. At-Least-Once Delivery Semantics

The forwarding protocol provides **at-least-once** delivery:

1. The connector polls unforwarded events (section 2).
2. The connector sends them to the SIEM.
3. The connector marks them forwarded (section 3).

If the connector crashes after step 2 but before step 3, the next poll cycle
will return the same events again. The SIEM connector **must be idempotent**:

- Use the `id` field as a deduplication key on the SIEM side.
- Alternatively, use `event_type` + `created_at` + a hash of `event_data` as a
  composite deduplication key if the SIEM does not support integer IDs.

The protocol does NOT guarantee exactly-once delivery. Connectors must tolerate
duplicates without data corruption.

---

## 6. Example Python Connector Skeleton

```python
#!/usr/bin/env python3
"""
Minimal audit-queue forwarding connector.

Polls runtime.audit_queue for unforwarded events, sends them to a
SIEM HTTP endpoint, then marks them forwarded.

Requirements: psycopg[binary], httpx
"""

import time
import httpx
import psycopg

# -- Configuration ----------------------------------------------------------
DB_DSN = "postgresql://audit_reader:changeme@localhost:5432/ldap"
SIEM_ENDPOINT = "https://siem.example.com/api/v1/events"
SIEM_API_KEY = "changeme"
POLL_INTERVAL_SECS = 10
BATCH_SIZE = 100

POLL_SQL = """
    SELECT id, event_type, event_data, created_at
    FROM runtime.audit_queue
    WHERE forwarded = FALSE
    ORDER BY created_at ASC
    LIMIT %s
"""

MARK_SQL = """
    UPDATE runtime.audit_queue
    SET forwarded = TRUE,
        forwarded_at = now()
    WHERE id = ANY(%s)
"""


def forward_batch(conn, http_client):
    """Poll one batch, forward to SIEM, mark as forwarded.

    Returns the number of events forwarded.
    """
    with conn.cursor() as cur:
        cur.execute(POLL_SQL, (BATCH_SIZE,))
        rows = cur.fetchall()

    if not rows:
        return 0

    # Build SIEM payload. Adjust to your SIEM's ingestion format.
    events = []
    ids = []
    for row_id, event_type, event_data, created_at in rows:
        ids.append(row_id)
        events.append({
            "id": row_id,
            "event_type": event_type,
            "event_data": event_data,
            "created_at": created_at.isoformat(),
        })

    # Send to SIEM. Raise on HTTP errors so we do NOT mark as forwarded.
    resp = http_client.post(
        SIEM_ENDPOINT,
        json={"events": events},
        headers={"Authorization": f"Bearer {SIEM_API_KEY}"},
        timeout=30,
    )
    resp.raise_for_status()

    # Mark forwarded only after successful delivery.
    with conn.cursor() as cur:
        cur.execute(MARK_SQL, (ids,))
    conn.commit()

    return len(ids)


def main():
    conn = psycopg.connect(DB_DSN, autocommit=False)
    http_client = httpx.Client()

    print("Audit forwarder started. Polling every "
          f"{POLL_INTERVAL_SECS}s, batch size {BATCH_SIZE}.")

    try:
        while True:
            try:
                count = forward_batch(conn, http_client)
                if count > 0:
                    print(f"Forwarded {count} events.")
            except httpx.HTTPStatusError as e:
                print(f"SIEM delivery failed: {e}. Will retry next cycle.")
            except psycopg.Error as e:
                print(f"Database error: {e}. Reconnecting.")
                conn = psycopg.connect(DB_DSN, autocommit=False)

            time.sleep(POLL_INTERVAL_SECS)
    finally:
        conn.close()
        http_client.close()


if __name__ == "__main__":
    main()
```

### Production hardening checklist

- Use TLS for both the database connection and the SIEM endpoint.
- Store credentials in a secrets manager, not in source code.
- Run the connector as a systemd service with restart-on-failure.
- Add Prometheus metrics (events_forwarded_total, poll_errors_total, batch_latency_seconds).
- Set an alerting rule if unforwarded event count exceeds a threshold.

---

## 7. Event Schema Reference

All events are serialized as JSON into the `event_data` JSONB column. The
`event_type` column contains the machine-readable name. Every event includes a
`timestamp` field (ISO 8601 UTC).

### `bind_attempt`

Authentication (LDAP Bind) attempt — logged for every attempt regardless of
outcome.

```json
{
  "event_type": "bind_attempt",
  "details": {
    "timestamp": "2026-03-19T14:30:00.123Z",
    "source_addr": "10.0.0.1:54321",
    "dn": "cn=jdoe,ou=users,dc=example,dc=com",
    "outcome": { "status": "Success" }
  }
}
```

Possible `outcome.status` values: `Success`, `InvalidCredentials`,
`AccountLocked`, `UserNotFound`, `AccountDisabled`, `RateLimited`,
`InternalError` (with additional `detail` field).

### `search_request`

A search operation was initiated.

```json
{
  "event_type": "search_request",
  "details": {
    "timestamp": "2026-03-19T14:30:01.456Z",
    "source_addr": "10.0.0.1:54321",
    "bound_dn": "cn=app,ou=services,dc=example,dc=com",
    "base_dn": "ou=users,dc=example,dc=com",
    "scope": "WholeSubtree",
    "filter_summary": "(uid=jdoe)"
  }
}
```

### `search_complete`

A search operation completed (success or error).

```json
{
  "event_type": "search_complete",
  "details": {
    "timestamp": "2026-03-19T14:30:01.512Z",
    "source_addr": "10.0.0.1:54321",
    "bound_dn": "cn=app,ou=services,dc=example,dc=com",
    "base_dn": "ou=users,dc=example,dc=com",
    "entries_returned": 1,
    "result_code": 0
  }
}
```

### `password_modify`

A Password Modify extended operation was processed.

```json
{
  "event_type": "password_modify",
  "details": {
    "timestamp": "2026-03-19T14:31:00.789Z",
    "source_addr": "10.0.0.2:44100",
    "broker_dn": "cn=broker,ou=services,dc=example,dc=com",
    "target_dn": "cn=jdoe,ou=users,dc=example,dc=com",
    "success": true,
    "failure_reason": null
  }
}
```

### `rate_limit_triggered`

A rate limit threshold was exceeded (NIST AC-7).

```json
{
  "event_type": "rate_limit_triggered",
  "details": {
    "timestamp": "2026-03-19T14:32:00.000Z",
    "source_addr": "10.0.0.99:60000",
    "dn": "cn=attacker,dc=example,dc=com",
    "attempt_count": 6,
    "window_secs": 300
  }
}
```

### `tls_error`

A TLS handshake or connection error occurred.

```json
{
  "event_type": "tls_error",
  "details": {
    "timestamp": "2026-03-19T14:33:00.000Z",
    "source_addr": "192.168.1.50:55555",
    "error_detail": "client offered TLS 1.0, minimum is 1.2"
  }
}
```

### `config_loaded`

Configuration was loaded at startup (NIST CM-6).

```json
{
  "event_type": "config_loaded",
  "details": {
    "timestamp": "2026-03-19T14:00:00.000Z",
    "config_path": "/etc/ldap-server/config.toml",
    "bind_addr": "0.0.0.0",
    "port": 636,
    "replication_enabled": true
  }
}
```

### `service_started`

The LDAPS service started successfully.

```json
{
  "event_type": "service_started",
  "details": {
    "timestamp": "2026-03-19T14:00:01.000Z",
    "bind_addr": "0.0.0.0",
    "port": 636,
    "tls_min_version": "1.2"
  }
}
```

### `service_stopped`

The LDAPS service is shutting down.

```json
{
  "event_type": "service_stopped",
  "details": {
    "timestamp": "2026-03-19T18:00:00.000Z",
    "reason": "SIGTERM"
  }
}
```

### `connection_opened`

A new client connection was established.

```json
{
  "event_type": "connection_opened",
  "details": {
    "timestamp": "2026-03-19T14:30:00.000Z",
    "source_addr": "10.0.0.1:54321"
  }
}
```

### `connection_closed`

A client connection was closed.

```json
{
  "event_type": "connection_closed",
  "details": {
    "timestamp": "2026-03-19T14:35:00.000Z",
    "source_addr": "10.0.0.1:54321",
    "messages_processed": 12,
    "duration_secs": 300.5
  }
}
```
