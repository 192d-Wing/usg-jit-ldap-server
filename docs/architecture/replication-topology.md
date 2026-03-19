# Replication Topology

This document describes the hub-and-spoke replication design for distributing
identity data from the central hub to 184 geographically distributed sites.

## Design Overview

```
                          ┌──────────────┐
                          │  CENTRAL HUB │
                          │              │
                          │  PostgreSQL  │
                          │  (Primary)   │
                          │              │
                          │  identity.*  │
                          │  repl_meta.* │
                          └──────┬───────┘
                                 │
              Pull-based replication (mTLS)
              Identity schema only
                                 │
        ┌────────────────────────┼────────────────────────┐
        │            │           │           │            │
   ┌────▼───┐  ┌────▼───┐  ┌────▼───┐  ┌────▼───┐       │
   │ Site 1 │  │ Site 2 │  │ Site 3 │  │ Site 4 │  ... Site 184
   │        │  │        │  │        │  │        │
   │identity│  │identity│  │identity│  │identity│
   │(replica│  │(replica│  │(replica│  │(replica│
   │runtime │  │runtime │  │runtime │  │runtime │
   │(local) │  │(local) │  │(local) │  │(local) │
   └────────┘  └────────┘  └────────┘  └────────┘
```

## Central Primary Responsibilities

The central hub PostgreSQL instance is the single source of truth for identity
data. It is responsible for:

1. **Authoritative identity storage**: Users, groups, group memberships, site
   assignments, and directory policies are mastered here.

2. **Change tracking**: Every mutation to identity data generates a change
   record with a monotonically increasing sequence number. The
   `repl_meta.change_log` table records: sequence number, table name, row
   primary key, operation (INSERT/UPDATE/DELETE), payload hash, and timestamp.

3. **Site registry**: Maintains the list of registered sites, their replication
   credentials (certificate CNs), and their last-acknowledged sequence numbers.

4. **Replication serving**: Exposes a replication API (HTTPS or direct
   PostgreSQL logical replication slot) that sites pull from. Serves change
   sets from a site's last-acknowledged sequence number forward.

5. **Stale site tracking**: Monitors each site's last pull timestamp and
   sequence lag. Alerts if a site falls behind a configurable threshold.

The central hub does NOT:
- Serve LDAP queries to end users
- Store or access password hashes
- Push data to sites (sites pull)
- Have any visibility into site runtime state

## Site Replica Responsibilities

Each of the 184 sites maintains a local PostgreSQL instance with two schemas:

### Identity Schema (Replicated)

- Contains a read-only copy of the subset of identity data relevant to that
  site (users assigned to the site, all groups those users belong to, and
  transitive group memberships).
- Updated exclusively by the local replication puller.
- The LDAP service has `SELECT`-only access.
- Site-scoped: a site only receives identity records for users and groups
  that are assigned to or relevant to that site.

### Runtime Schema (Site-Local)

- Contains ephemeral password hashes, bind event logs, and audit queue entries.
- Written by the JIT Broker (password issuance) and the LDAP service (bind
  events, audit entries).
- Never leaves the site. Never included in any replication channel.

## What Replicates

| Data Type | Replicates | Direction | Notes |
|---|---|---|---|
| Users (`identity.users`) | Yes | Central → Site | User DN, attributes, status, site assignments |
| Groups (`identity.groups`) | Yes | Central → Site | Group DN, attributes, membership type |
| Group Memberships (`identity.memberships`) | Yes | Central → Site | User-to-group mappings |
| Site Assignments (`identity.site_assignments`) | Yes | Central → Site | Which users are assigned to which sites |
| Directory Policies (`identity.policies`) | Yes | Central → Site | Password policy params, rate limit configs |
| Replication Metadata (`repl_meta.*`) | Yes | Central → Site | Sequence numbers, change log (for the pull protocol) |

## What Does NOT Replicate

| Data Type | Replicates | Reason |
|---|---|---|
| Password Hashes (`runtime.credentials`) | **Never** | Ephemeral passwords are site-local by design. Replication would violate the security model. |
| Bind Events (`runtime.bind_events`) | **Never** | Authentication events are site-local audit records. |
| Audit Queue (`runtime.audit_queue`) | **Never** | Audit events are forwarded to a central SIEM via a separate mechanism, not via LDAP replication. |
| Session State | **Never** | Per-connection, in-memory only. Not persisted. |
| TLS Material | **Never** | Certificates and private keys are provisioned per-site by PKI infrastructure. |
| Configuration | **No** | Site configuration is managed by the site's configuration management system (Ansible, etc.), not by LDAP replication. Policies that affect LDAP behavior (rate limits, TTLs) replicate via `identity.policies`. |

## Replication Protocol

### Pull Model

Sites initiate replication pulls. The central hub never pushes.

```
Site                                Central Hub
  │                                      │
  │── mTLS connect ─────────────────────►│
  │   (site cert CN = site_id)           │
  │                                      │
  │── GET changes since seq=N ──────────►│
  │                                      │
  │◄── change set (seq N+1..N+M) ───────│
  │    + payload SHA-256 digest          │
  │                                      │
  │── ACK seq=N+M ─────────────────────►│
  │                                      │
  │── disconnect ───────────────────────►│
  │                                      │
```

### Pull Schedule

- **Normal mode**: Every 60 seconds (configurable per site).
- **Catchup mode**: Continuous pulling (no delay between pulls) when the site
  is more than 100 sequence numbers behind.
- **Backoff mode**: Exponential backoff (up to 5 minutes) when the central hub
  is unreachable.

### Change Set Format

Each change set contains:

1. **Sequence range**: Start and end sequence numbers.
2. **Operations**: Ordered list of (sequence, table, pk, operation, row_data).
3. **Digest**: SHA-256 over the serialized operations.
4. **Timestamp**: Hub-side timestamp of the last operation in the set.

Sites apply operations in sequence order within a single database transaction.
If any operation fails, the entire change set is rolled back and the pull is
retried.

## WAN Failure Behavior and Local Survivability

### During WAN Outage

When a site cannot reach the central hub:

1. **LDAP service continues operating.** Bind and Search operations use the
   locally cached identity data and locally stored credentials. There is no
   dependency on the central hub for runtime operations.

2. **Replication puller enters backoff mode.** It retries with exponential
   backoff and logs each failure. The `replication_health` table tracks the
   last successful pull time and current lag.

3. **JIT Broker continues operating locally.** The Broker issues passwords
   to the local runtime schema. This does not require WAN connectivity.

4. **Identity data becomes stale.** Users added or removed at the central
   hub after the WAN failure will not appear at the site until replication
   resumes. This is an accepted trade-off for local survivability.

5. **Audit events queue locally.** Events are written to the local
   `runtime.audit_queue` and forwarded to the central SIEM when connectivity
   is restored.

### Upon WAN Restoration

1. The replication puller detects connectivity and enters catchup mode.
2. It pulls all missed change sets in sequence order.
3. Each change set is applied transactionally.
4. Once the site reaches the current hub sequence, it returns to normal mode.
5. The `replication_health` table is updated and the lag metric drops to zero.

### Survivability Guarantees

| Scenario | Behavior |
|---|---|
| WAN down, user exists locally, valid password | Bind succeeds |
| WAN down, user exists locally, no password issued | Bind fails (no credential to verify) |
| WAN down, user added at hub after outage | User not visible at site until replication resumes |
| WAN down, user removed at hub after outage | User remains visible at site until replication resumes (stale) |
| WAN down, password expires during outage | Bind fails (TTL enforced locally) |

## Stale Replica Detection and Handling

### Detection

Each site tracks replication health in the `runtime.replication_health` table:

| Column | Description |
|---|---|
| `last_pull_success` | Timestamp of the last successful replication pull |
| `last_pull_attempt` | Timestamp of the last attempted pull |
| `last_sequence` | Last applied sequence number |
| `hub_sequence` | Last known hub sequence number (from the most recent pull response) |
| `lag_seconds` | Estimated lag in seconds |
| `lag_sequences` | Number of unapplied sequence numbers |
| `status` | `healthy`, `lagging`, `stale`, `disconnected` |

### Staleness Thresholds (Configurable)

| Status | Condition | Action |
|---|---|---|
| `healthy` | lag_sequences < 100 AND lag_seconds < 300 | Normal operation |
| `lagging` | lag_sequences >= 100 OR lag_seconds >= 300 | Enter catchup mode. Emit warning metric. |
| `stale` | lag_seconds > 3600 | Emit alert. Optionally restrict new Binds to already-cached users only. |
| `disconnected` | last_pull_success > 86400s ago | Emit critical alert. Site operates on cached data. Operator intervention recommended. |

### Operator Response

When a site enters `stale` or `disconnected` status:

1. Monitoring systems (Prometheus/Grafana) fire alerts.
2. The LDAP service continues operating (fail-open for availability; identity
   data may be stale but passwords are still site-local and valid).
3. Operators investigate WAN connectivity, hub health, and certificate
   validity.
4. Once resolved, the site catches up automatically.

## Reconciliation Strategy

Periodic full reconciliation detects drift between the central hub and site
replicas that may not be caught by incremental replication.

### Full Reconciliation Process

1. **Trigger**: Scheduled (e.g., weekly) or operator-initiated.
2. **Hub generates manifest**: A sorted list of (table, pk, row_hash) for all
   identity records scoped to the site.
3. **Site generates manifest**: Same format from its local identity schema.
4. **Diff**: The puller compares manifests and identifies:
   - Missing rows (present at hub, absent at site)
   - Extra rows (absent at hub, present at site — should not happen)
   - Modified rows (hash mismatch)
5. **Repair**: Missing and modified rows are pulled from the hub. Extra rows
   are deleted from the site.
6. **Audit**: Reconciliation results are logged, including counts of each
   repair type.

### Reconciliation Safeguards

- Maximum repair batch size: if drift exceeds a configurable threshold (e.g.,
  1000 rows), reconciliation pauses and alerts. This guards against a
  corrupted manifest causing mass deletion.
- Reconciliation runs in a separate database transaction from normal
  replication.
- Reconciliation does not touch the runtime schema.

## Operational Observability

### Metrics (Prometheus)

| Metric | Type | Description |
|---|---|---|
| `ldap_repl_last_pull_success_timestamp` | Gauge | Timestamp of last successful pull |
| `ldap_repl_lag_sequences` | Gauge | Sequence number lag behind hub |
| `ldap_repl_lag_seconds` | Gauge | Estimated time lag behind hub |
| `ldap_repl_pull_duration_seconds` | Histogram | Duration of each pull operation |
| `ldap_repl_pull_errors_total` | Counter | Count of failed pull attempts |
| `ldap_repl_changeset_size` | Histogram | Number of operations per change set |
| `ldap_repl_reconciliation_drift_rows` | Gauge | Rows repaired in last reconciliation |
| `ldap_repl_status` | Gauge | Encoded status (0=healthy, 1=lagging, 2=stale, 3=disconnected) |

### Logs

All replication events are logged as structured JSON:

```json
{
  "event": "replication_pull",
  "site_id": "site-042",
  "status": "success",
  "seq_start": 145023,
  "seq_end": 145047,
  "rows_applied": 24,
  "duration_ms": 312,
  "timestamp": "2026-03-19T14:30:00Z"
}
```

### Alerting Rules (Examples)

| Alert | Condition | Severity |
|---|---|---|
| ReplicationLagging | `ldap_repl_lag_seconds > 300` for 5 min | Warning |
| ReplicationStale | `ldap_repl_lag_seconds > 3600` for 10 min | Critical |
| ReplicationDisconnected | `ldap_repl_last_pull_success_timestamp < now() - 86400` | Critical |
| ReconciliationDrift | `ldap_repl_reconciliation_drift_rows > 100` | Warning |
| PullErrors | `rate(ldap_repl_pull_errors_total[5m]) > 0.5` | Warning |

## Scaling Considerations

With 184 sites pulling from a single central hub:

- **Connection concurrency**: At 60-second intervals with ~1-second pull
  duration, average concurrent connections to the hub is approximately 3.
  Peak may reach 10-15 if pulls cluster. This is well within PostgreSQL's
  connection capacity.

- **Bandwidth**: Identity change sets are typically small (tens of rows per
  minute). Full reconciliation manifests for a large site may be several MB.
  Scheduled during off-peak hours.

- **Hub read load**: Replication queries hit the `identity` schema and
  `repl_meta.change_log`. An index on `(sequence_number)` ensures efficient
  range scans. A read replica of the hub database can serve replication
  queries if load becomes a concern.

- **Site-scoped replication**: Each site only receives records relevant to
  its assigned users, reducing payload size compared to full replication.
