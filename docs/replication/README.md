# Replication Design: USG JIT LDAP Server

## Overview

The USG JIT LDAP Server replicates **identity data only** from a single central
hub to 184 geographically distributed site replicas. Replication is pull-based:
each site independently fetches incremental changes from the central hub on a
configurable interval.

This design prioritizes:

- **Local survivability**: sites continue serving identity lookups during WAN outages.
- **Data segregation**: passwords, bind events, and audit data never leave the site.
- **Simplicity**: one authoritative source, no multi-master conflict resolution.
- **Auditability**: every replication event is tracked with sequence numbers and timestamps.

## Topology

```
                    ┌─────────────────────────────┐
                    │        Central Hub           │
                    │  ┌───────────────────────┐   │
                    │  │ PostgreSQL (Primary)   │   │
                    │  │  identity.*            │   │
                    │  │  replication_metadata  │   │
                    │  │  replication_log       │   │
                    │  └───────────┬───────────┘   │
                    │              │                │
                    │  ┌───────────┴───────────┐   │
                    │  │ Replication Endpoint   │   │
                    │  │ (PostgreSQL listen or  │   │
                    │  │  read-replica conn)    │   │
                    │  └───────────┬───────────┘   │
                    └──────────────┼────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
     ┌────────▼────────┐ ┌────────▼────────┐  ┌────────▼────────┐
     │   Site 001       │ │   Site 002       │  │   Site 184       │
     │ ┌──────────────┐ │ │ ┌──────────────┐ │  │ ┌──────────────┐ │
     │ │ Replication  │ │ │ │ Replication  │ │  │ │ Replication  │ │
     │ │ Puller       │ │ │ │ Puller       │ │  │ │ Puller       │ │
     │ └──────┬───────┘ │ │ └──────┬───────┘ │  │ └──────┬───────┘ │
     │ ┌──────▼───────┐ │ │ ┌──────▼───────┐ │  │ ┌──────▼───────┐ │
     │ │ PostgreSQL   │ │ │ │ PostgreSQL   │ │  │ │ PostgreSQL   │ │
     │ │ identity.*   │ │ │ │ identity.*   │ │  │ │ identity.*   │ │
     │ │ runtime.*    │ │ │ │ runtime.*    │ │  │ │ runtime.*    │ │
     │ └──────────────┘ │ │ └──────────────┘ │  │ └──────────────┘ │
     └──────────────────┘ └──────────────────┘  └──────────────────┘

     Pull direction: Site ──GET──► Central (never push)
     Each site pulls independently on a staggered schedule.
```

## Pull-Based Replication Protocol

### Why Pull (Not Push)

- **Firewall-friendly**: sites initiate outbound connections; central does not
  need inbound access to site networks.
- **Site autonomy**: each site controls its own sync cadence and retry logic.
- **No fan-out burden**: central does not need to track 184 push targets.
- **NAT/VPN compatible**: works through typical site network configurations.

### Protocol Flow

```
Site Puller                                Central Hub
    │                                           │
    │  1. Connect to central PostgreSQL         │
    │─────────────────────────────────────────►  │
    │                                           │
    │  2. SELECT changes WHERE seq > last_seq   │
    │─────────────────────────────────────────►  │
    │                                           │
    │  3. Return batch of ReplicationChange     │
    │  ◄─────────────────────────────────────── │
    │                                           │
    │  4. BEGIN transaction on local DB          │
    │  5. Apply changes (upsert/delete)         │
    │  6. UPDATE replication_metadata            │
    │  7. COMMIT                                │
    │                                           │
    │  8. Report health metrics                 │
    │                                           │
```

### Sequence Number Tracking

Every identity mutation at the central hub is assigned a monotonically
increasing sequence number via a PostgreSQL `BIGSERIAL` column on the
`replication_log` table. Sites track their last-consumed sequence number
in a local `replication_metadata` table.

**Central schema (replication_log):**

```sql
CREATE TABLE replication_log (
    seq_number  BIGSERIAL PRIMARY KEY,
    change_type TEXT NOT NULL,        -- 'user_upsert', 'user_delete', etc.
    entity_id   UUID NOT NULL,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_replication_log_seq ON replication_log (seq_number);
```

**Site schema (replication_metadata):**

```sql
CREATE TABLE replication_metadata (
    site_id            UUID PRIMARY KEY,
    last_sequence_number BIGINT NOT NULL DEFAULT 0,
    last_sync_at       TIMESTAMPTZ,
    last_sync_duration_ms BIGINT,
    last_error         TEXT
);
```

### Incremental Sync

Each pull cycle:

1. Read `last_sequence_number` from local `replication_metadata`.
2. Query central: `SELECT * FROM replication_log WHERE seq_number > $1 ORDER BY seq_number ASC LIMIT $2`.
3. Apply changes in sequence order within a single local transaction.
4. Update `last_sequence_number` to the highest consumed sequence number.
5. If more rows remain (batch was full), immediately start another pull cycle.

### Full Re-Sync

Triggered when:

- Site database is empty or corrupted.
- `last_sequence_number` references a sequence that has been pruned from central.
- Operator manually requests it.

Full re-sync sets `last_sequence_number = 0` and truncates local identity
tables before re-applying. This is done within a transaction to avoid serving
partial data during re-sync.

## Data Scope

### Replicated (Identity Schema)

| Table | Content | Justification |
|-------|---------|---------------|
| `identity.users` | User records (uid, DN, attributes) | Required for LDAP Search at every site |
| `identity.groups` | Group records (cn, DN, member lists) | Required for group-based access control |
| `identity.memberships` | User-to-group mappings | Denormalized for efficient search |
| `identity.site_policies` | Per-user, per-site access grants | Controls who can authenticate at which site |

### Never Replicated

| Data | Location | Justification |
|------|----------|---------------|
| Password hashes | `runtime.passwords` (site-local) | NIST IA-5(2): credential material must not traverse network boundaries unnecessarily. Passwords are JIT-issued per-site. |
| Bind events | `runtime.bind_events` (site-local) | AU-3: audit records stay where they are generated for integrity. |
| Audit queue | `runtime.audit_queue` (site-local) | AU-9: audit data must not be modifiable by replication processes. |
| Rate limit state | In-memory (site-local) | Ephemeral runtime state, no persistence needed. |
| TLS session cache | In-memory (site-local) | SC-8: session keys are never shared between sites. |
| Replication metadata | `replication_metadata` (site-local) | Tracks local sync state only. |

## WAN Failure Behavior

### During a WAN Outage

1. **Site continues serving**: the LDAPS listener and all LDAP operations remain
   fully functional using locally-cached identity data and locally-stored
   passwords.
2. **Replication puller enters retry loop**: exponential backoff with jitter,
   logging each failed attempt.
3. **Staleness clock starts**: the `last_sync_at` timestamp stops advancing.
   Health checks begin reporting staleness.
4. **No new identities**: users provisioned at central after the outage began
   will not appear at the site until WAN restores. Existing users are unaffected.
5. **No password impact**: passwords are site-local and completely independent
   of replication. JIT Broker can continue issuing passwords if it can reach
   the local PostgreSQL.

### Staleness Detection and Alerting

| Threshold | Action |
|-----------|--------|
| `pull_interval * 3` | Log warning: replication is behind |
| `stale_threshold` (configurable, default 1 hour) | Health endpoint reports `Stale` status |
| `stale_threshold * 2` | Alert: site is operating on significantly stale data |
| `stale_threshold * 4` | Critical alert: manual investigation recommended |

Staleness is computed as: `now() - last_sync_at`.

### Automatic Recovery

When WAN connectivity restores:

1. Next pull cycle succeeds, fetching all accumulated changes.
2. If the gap is large, multiple batch pulls occur back-to-back.
3. `ReplicationStatus` transitions from `Stale` or `Error` back to `Synced`.
4. Health metrics reflect recovery: `consecutive_failures` resets to 0.
5. No manual intervention required for normal recovery.

## Failure Modes and Mitigations

See [failure-modes.md](failure-modes.md) for the detailed failure mode analysis.

Summary of key failure modes:

| Failure | Impact | Core Mitigation |
|---------|--------|-----------------|
| Central hub down | No new identity data at any site | Sites serve stale data; alerting triggers ops response |
| Site DB corruption | Site cannot serve any requests | Full re-sync from central; site restart |
| Network partition | Site operates on stale identity data | Bounded staleness; local survivability design |
| Slow replication | Identity changes delayed at site | Batch size tuning; monitoring; staggered pulls |
| Split-brain | N/A by design | Central is sole authority; sites are read-only for identity |

## Reconciliation Strategy

After an outage:

1. **Incremental catch-up**: sites pull all changes accumulated during the outage
   via normal sequence-number-based incremental sync. No special reconciliation
   protocol is needed because the central hub maintained a continuous log.
2. **Sequence gap detection**: if the central has pruned log entries that a site
   has not yet consumed (i.e., the site's `last_sequence_number` is below the
   minimum available in `replication_log`), the site triggers a full re-sync.
3. **Idempotent application**: all change application is idempotent (UPSERT for
   creates/updates, DELETE with WHERE clause for deletes). Re-applying a change
   is safe.
4. **No conflict resolution needed**: central is authoritative. Sites never
   modify identity data. There are no write-write conflicts to resolve.

## Operational Observability

### Metrics

All metrics are emitted via `tracing` spans and events, suitable for Prometheus
scraping via a metrics exporter.

| Metric | Type | Description |
|--------|------|-------------|
| `replication_pull_duration_seconds` | Histogram | Time taken for each pull cycle |
| `replication_changes_applied_total` | Counter | Total identity changes applied |
| `replication_sequence_number` | Gauge | Current sequence number at the site |
| `replication_consecutive_failures` | Gauge | Number of consecutive failed pulls |
| `replication_last_success_timestamp` | Gauge | Unix timestamp of last successful sync |
| `replication_staleness_seconds` | Gauge | Seconds since last successful sync |
| `replication_full_resync_total` | Counter | Number of full re-syncs triggered |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `ReplicationStale` | `staleness_seconds > stale_threshold` | Warning |
| `ReplicationDown` | `consecutive_failures > max_retry_attempts` | Critical |
| `ReplicationFullResync` | Full re-sync triggered | Info |
| `ReplicationSequenceGap` | Detected pruned log entries | Warning |

### Health Endpoint

Each site exposes a `HealthReport` struct (see `src/replication/health.rs`)
that provides:

- Current `ReplicationStatus` (Synced, Syncing, Stale, Error)
- Last sync timestamp
- Current sequence number
- Consecutive failure count
- Average sync duration
- Staleness flag

## Scaling Considerations for 184 Sites

### Staggered Pull Intervals

To avoid thundering herd on the central hub:

- Each site computes its pull offset as: `(site_index % spread_factor) * (pull_interval / spread_factor)`
- Default `pull_interval`: 60 seconds
- Default `spread_factor`: 12 (distributes 184 sites across 12 offset groups of ~15 sites each)
- Result: at most ~15 sites pulling simultaneously

### Connection Limits

- Central PostgreSQL `max_connections` must accommodate concurrent site pulls.
- Recommendation: dedicated connection pool for replication with
  `max_connections = 20` (covers peak concurrent pulls with headroom).
- Sites use a single connection per pull cycle (no connection pooling needed
  for the replication connection itself).

### Batch Size Tuning

- Default batch size: 1000 changes per pull.
- Sites with large backlogs (after outage) pull in rapid succession until caught up.
- Central should have an index on `replication_log.seq_number` for efficient range queries.

### Log Retention and Pruning

- Central retains `replication_log` entries for a configurable period (default: 7 days).
- A background job prunes entries older than the retention period.
- Before pruning, verify that all sites have consumed entries beyond the prune point
  (query minimum `last_sequence_number` across all registered sites).
- If a site has not synced in > retention period, it will require a full re-sync.

## NIST SP 800-53 Rev. 5 Control Mappings

| Control | Relevance to Replication |
|---------|------------------------|
| SC-8 (Transmission Confidentiality) | Replication channel uses TLS-encrypted PostgreSQL connections |
| SI-7 (Software, Firmware, and Information Integrity) | Sequence numbers ensure ordering; idempotent application prevents corruption |
| CP-9 (System Backup) | Local identity data serves as operational backup during WAN loss |
| CP-10 (System Recovery) | Automatic incremental catch-up and full re-sync capabilities |
| AC-4 (Information Flow Enforcement) | Only identity data crosses trust boundaries; passwords/audit stay local |
| AU-9 (Protection of Audit Information) | Audit data is never replicated; remains at originating site |
| IA-5 (Authenticator Management) | Password hashes never replicated; JIT-issued per-site |
| SC-7 (Boundary Protection) | Sites initiate outbound connections only; central does not push into site networks |
