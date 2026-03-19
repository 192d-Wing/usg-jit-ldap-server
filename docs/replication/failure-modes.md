# Replication Failure Mode Analysis

## Failure Mode Table

| # | Failure | Detection | Impact | Mitigation | Recovery |
|---|---------|-----------|--------|------------|----------|
| 1 | **Central hub down** | Puller connection refused/timeout; `consecutive_failures` increments | No new identity data at any site. Existing data continues to serve. Password operations unaffected. | Sites designed for local survivability. Staleness alerting triggers ops response. Redundant central infrastructure (HA PostgreSQL) recommended. | When central restores, sites resume incremental pull automatically. No manual intervention needed unless log was lost. |
| 2 | **Site down** | Site health check fails; no pull attempts logged | Site cannot serve LDAP requests. Other sites unaffected. Central unaware (pull-based). | Local HA (process supervision, container restart). Site monitoring independent of replication. | Site restarts, puller resumes from last `last_sequence_number`. Catch-up is automatic. |
| 3 | **WAN partition** | Puller connection timeout; `replication_staleness_seconds` increases | Site operates on stale identity data. New users/groups provisioned after partition are unavailable at the site. Passwords and auth continue working for known users. | Bounded staleness with configurable threshold. Sites serve local data indefinitely. Staleness alerts inform operators. | Partition heals, next pull cycle succeeds. Incremental catch-up resumes. Multiple rapid batches if backlog is large. |
| 4 | **Slow replication** | `replication_pull_duration_seconds` exceeds SLO; sequence number falls behind | Identity changes are delayed at the site. Users may see stale group memberships or missing new accounts. | Batch size tuning. Index optimization on central `replication_log`. Monitor pull duration trends. Stagger site pull intervals to reduce central load. | Optimize queries, increase batch size, or reduce pull interval. If persistent, investigate central DB performance. |
| 5 | **Site DB corruption** | Application errors on identity queries; integrity check failures; puller apply errors | Site cannot serve correct LDAP responses. May serve incorrect data. | Health check detects errors and marks site as unhealthy. Puller stops applying changes and reports error status. | Operator triggers full re-sync: truncate local identity tables, reset `last_sequence_number` to 0, puller rebuilds from central. Automated full re-sync if sequence gap detected. |
| 6 | **Clock skew** | Monitoring of NTP sync status; timestamps in health reports appear inconsistent | Staleness calculations may be inaccurate (site thinks it is more or less stale than reality). Sequence-number-based sync is unaffected (sequence numbers are not time-dependent). | Replication correctness depends on sequence numbers, not timestamps. Timestamps used only for observability. Require NTP on all nodes. | Correct NTP configuration. Staleness thresholds have enough margin to tolerate minor skew. |
| 7 | **Replication loop prevention** | N/A (prevented by design) | N/A | Loops are architecturally impossible: central is the sole writer of `replication_log`, sites are read-only consumers of identity data. There is no site-to-site or site-to-central replication path. | N/A |
| 8 | **Central log pruning before site sync** | Puller queries for `seq_number > last_seq` and receives empty result while central has higher sequences; or explicit gap detection query | Site cannot incrementally sync. Missing changes between site's last sequence and central's earliest available. | Retain logs for configurable period (default 7 days). Monitor minimum site sequence across all sites before pruning. Alert if any site is at risk of falling behind retention window. | Full re-sync triggered automatically when gap detected. Operator notified. |
| 9 | **Replication endpoint overload** | Central connection pool exhaustion; connection refused errors from multiple sites simultaneously | Multiple sites fail to pull simultaneously. Staleness increases across affected sites. | Staggered pull intervals (spread 184 sites across offset groups). Dedicated connection pool on central for replication (default limit: 20). Rate limiting on replication endpoint. | Reduce concurrent pull load. Increase central pool size if hardware permits. Extend pull interval temporarily. |
| 10 | **Poisoned replication data** | Integrity check on applied data (schema validation, constraint violations); anomaly detection on change volume | Corrupted or malicious identity data propagated to sites. Incorrect authentication decisions. | Central is the sole authority; changes are validated at central before writing to `replication_log`. Sites validate schema constraints on apply. Failed constraint violations roll back the entire batch. NIST SI-7 integrity controls. | Identify and fix corrupted data at central. Sites will receive corrective changes on next pull. If widespread, operator may trigger full re-sync across affected sites. |
| 11 | **Transaction deadlock during apply** | PostgreSQL deadlock detection; apply returns error | Current pull batch fails. Changes not applied. | Retry with exponential backoff. Apply changes in deterministic order (sorted by entity_id) to minimize deadlock probability. Single-threaded apply per site eliminates most deadlock scenarios. | Automatic retry on next pull cycle. Deadlocked transaction is rolled back by PostgreSQL. |
| 12 | **Network degradation (high latency/packet loss)** | Pull duration increases; intermittent connection resets; TCP timeout | Replication slows but may still function. Increased staleness during degradation. | Configurable connection and query timeouts. TCP keepalive settings. Batch size can be reduced to keep individual pull cycles shorter. | Network recovery restores normal pull performance. Backlog cleared via rapid successive pulls. |

## Failure Severity Classification

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | Site cannot serve LDAP requests at all | Site DB corruption, site process crash |
| **High** | Identity data staleness exceeds SLO | Central down > stale_threshold, WAN partition > stale_threshold |
| **Medium** | Replication degraded but within SLO | Slow replication, intermittent connectivity |
| **Low** | Observability concern, no operational impact | Clock skew, minor latency increase |
| **Info** | Expected operational event | Full re-sync triggered, log pruning executed |

## Split-Brain Prevention

Split-brain is prevented by architectural design:

1. **Central is the sole authority** for identity data. All identity mutations
   (user create, group modify, policy change) occur at the central hub and are
   written to `replication_log`.

2. **Sites are read-only consumers** of identity data. The LDAP server at each
   site does not implement Add, Delete, or Modify operations for identity
   objects. There is no code path to write to identity tables except through
   the replication puller.

3. **No site-to-site communication**: sites only communicate with central.
   There is no gossip protocol, no peer sync, no forwarded writes.

4. **No site-to-central writeback**: sites do not push data to central. The
   replication channel is strictly one-directional (central -> site).

This means:

- There is never a conflict between two writers.
- There is never ambiguity about which version of a record is authoritative.
- During a partition, sites serve stale-but-consistent data.
- After a partition heals, sites converge to the central state automatically.

## Operational Runbook Summary

### Scenario: Site reports Stale status

1. Check WAN connectivity to central from the site.
2. Check central PostgreSQL availability.
3. Review puller logs for error messages.
4. If WAN is down: wait for network team; site continues serving with local data.
5. If central is down: escalate to central ops team.

### Scenario: Full re-sync needed

1. Confirm the site should be re-synced (not just temporarily behind).
2. Set site LDAP server to maintenance mode (optional, for consistency).
3. Reset `last_sequence_number` to 0 in `replication_metadata`.
4. Puller will automatically truncate identity tables and rebuild.
5. Monitor progress via `replication_sequence_number` metric.
6. Verify site is serving correct data after re-sync completes.

### Scenario: Central log pruning alert

1. Identify which site(s) have a `last_sequence_number` below the central's
   minimum `seq_number`.
2. Determine if the site(s) are reachable and why they fell behind.
3. If site is reachable: it will auto-trigger full re-sync on next pull.
4. If site is unreachable: note for when it comes back online.
5. Review log retention policy; consider extending if sites frequently fall behind.
