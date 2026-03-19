# Replication Recovery

This document describes how to detect and recover from replication failures in the USG JIT LDAP Server.

---

## Overview

The LDAP server periodically pulls identity data from a central authority. Each pull fetches a batch of changes since the last known sequence number. If the WAN link to central is interrupted, the local site continues to serve requests using its existing data. When connectivity is restored, replication catches up automatically.

---

## Detecting Stale Replication

### Health Metrics

Monitor the following indicators:

- **`replication_last_success_timestamp`** — if this is older than `stale_threshold_secs` (default: 900s), the site is stale.
- **`replication_last_sequence`** — the most recent sequence number received from central.
- **`replication_consecutive_failures`** — count of consecutive failed pull attempts.

### Log Signals

```bash
# Check for replication warnings
journalctl -u ldap-server --since "-1hour" | grep -i "replication"

# Look for specific failure patterns
grep '"event":"replication_pull_failed"' /var/log/ldap-server/audit.jsonl | tail -10
```

### Manual Health Query

```sql
-- Check the replication tracking table
SELECT site_id, last_sequence, last_pull_at, last_success_at
FROM runtime.replication_state;
```

If `last_success_at` is significantly older than `pull_interval_secs`, the site is stale.

---

## WAN Outage Behavior

When the WAN link to the central authority is down:

1. **Site continues operating.** All LDAP operations (BIND, SEARCH) continue using locally replicated data.
2. **JIT credential provisioning continues.** New credentials are created in the local `runtime` schema and do not depend on WAN connectivity.
3. **Replication pulls fail gracefully.** Each failed pull is logged and retried on the next interval (up to `max_retry_attempts` per cycle).
4. **Data becomes progressively stale.** New identities or changes made at central will not be visible until replication resumes.

**Important:** The site never refuses service due to stale data. Staleness is a monitoring concern, not an operational halt.

---

## Automatic Catch-Up on WAN Restore

When connectivity is restored:

1. The next scheduled replication pull succeeds.
2. The server fetches changes in batches (configured by `batch_size`, default 500) starting from its last known sequence number.
3. Multiple batches are pulled in rapid succession until the site is fully caught up.
4. The `replication_last_success_timestamp` metric resets, clearing any stale alerts.

No manual intervention is required for automatic catch-up.

---

## Manual Full Re-Sync Procedure

If the replication state is corrupted or the sequence gap is too large for incremental catch-up, perform a full re-sync:

### 1. Stop the LDAP Server

```bash
sudo systemctl stop ldap-server
```

### 2. Reset the Replication State

```sql
-- Clear the replication tracking so the next pull fetches everything
-- WARNING: This causes a full reload from central on next start
UPDATE runtime.replication_state
SET last_sequence = 0, last_pull_at = NULL, last_success_at = NULL
WHERE site_id = 'site-alpha';
```

### 3. Optionally Truncate and Reload Identity Data

If data integrity is in question:

```sql
-- Remove all replicated identity data
TRUNCATE TABLE identity.users CASCADE;
TRUNCATE TABLE identity.groups CASCADE;
TRUNCATE TABLE identity.group_members CASCADE;
```

### 4. Start the LDAP Server

```bash
sudo systemctl start ldap-server
```

### 5. Monitor the Re-Sync

```bash
# Watch replication progress
journalctl -u ldap-server -f | grep -i "replication"
```

The full re-sync may take several minutes depending on the size of the identity dataset and WAN bandwidth.

---

## Sequence Number Gap Detection

Sequence gaps indicate that one or more change events were skipped during replication.

### Detection

```sql
-- Compare local sequence to what central reports as current
-- (requires manual query to central API or a monitoring dashboard)
SELECT last_sequence FROM runtime.replication_state WHERE site_id = 'site-alpha';
```

Compare this value against the central authority's current sequence number. A gap larger than a few batch sizes may warrant investigation.

### Common Causes

| Cause | Resolution |
|-------|------------|
| Transient network error during a batch | Automatic retry on next interval; no action needed |
| Central API returned an error mid-batch | Check central service health; retry will recover |
| Central performed a data compaction | May require a full re-sync if old sequences are no longer available |
| Local database was restored from a backup | Reset `last_sequence` to the backup's point-in-time and let catch-up proceed |

### Resolution for Persistent Gaps

If the gap cannot be resolved by incremental catch-up (e.g. central has compacted past the local sequence), follow the **Manual Full Re-Sync Procedure** above.

---

## Verifying Replication Health After Recovery

After any recovery action, confirm that replication is healthy:

### 1. Check Metrics

- `replication_last_success_timestamp` should be recent (within `pull_interval_secs`).
- `replication_consecutive_failures` should be 0.

### 2. Spot-Check Data

```sql
-- Pick a known user and verify their data matches central
SELECT uid, display_name, email, updated_at
FROM identity.users
WHERE uid = 'known-test-user';
```

### 3. Verify Sequence Continuity

```sql
SELECT last_sequence, last_success_at
FROM runtime.replication_state
WHERE site_id = 'site-alpha';
```

The sequence should be advancing on each pull interval.

### 4. Test End-to-End

```bash
# Search for a recently-added identity to confirm it replicated
ldapsearch -H ldaps://ldap.example.gov:636 \
  -D "cn=test-broker,ou=brokers,dc=example,dc=gov" \
  -w "PASSWORD" \
  -b "ou=people,dc=example,dc=gov" \
  "(uid=recently-added-user)"
```
