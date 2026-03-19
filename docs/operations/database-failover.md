# Database Failover

This document describes PostgreSQL failover behavior and recovery procedures for the USG JIT LDAP Server.

---

## Architecture Overview

The LDAP server connects to PostgreSQL via an `sqlx` connection pool. The connection URL is configured in `config.toml` under `[database].url`. In a high-availability deployment, PostgreSQL typically runs behind a VIP, DNS alias, or connection proxy (e.g. PgBouncer, HAProxy) that redirects traffic during failover.

---

## Failover Detection

### How the Server Detects a Failure

- The `sqlx` pool monitors connection health. When a query fails with a connection error, the pool marks that connection as broken and drops it.
- Subsequent operations will attempt to acquire a new connection from the pool, which triggers a reconnect to the database URL.
- If the database URL resolves to a new primary (via DNS or VIP failover), new connections will go to the new primary automatically.

### Symptoms of an In-Progress Failover

- LDAP BIND and SEARCH operations return transient errors.
- Audit log entries show database connection errors.
- The health endpoint (when implemented) reports degraded status.
- Connection pool metrics show elevated acquire times or pool exhaustion.

---

## Connection Pool Behavior During Failover

| Phase | Behavior |
|-------|----------|
| **Failure detected** | Active queries on broken connections return errors. The pool evicts dead connections. |
| **Reconnecting** | New connection attempts target the database URL. If DNS/VIP has not yet flipped, these attempts fail and are retried on next operation. |
| **New primary available** | The pool gradually fills with connections to the new primary. No manual intervention is required. |
| **Pool recovery** | Within a few seconds of the new primary being reachable, normal operation resumes. |

### Key Pool Settings

- `max_connections` — caps the pool size. During failover, all slots may be briefly empty.
- The pool's internal `min_connections` (if set) controls eager reconnection.
- `sqlx` uses exponential backoff internally when reconnecting.

---

## Automatic Reconnection Behavior

The `sqlx` pool handles reconnection transparently:

1. A broken connection is removed from the pool.
2. The next call to `pool.acquire()` opens a new TCP connection to the configured URL.
3. If the DNS record or VIP now points to the new primary, the connection lands on the correct host.
4. No application restart is required.

**Caveat:** If the database URL contains a hardcoded IP address (rather than a hostname), automatic failover will not work. Always use a DNS name or VIP.

---

## Manual Verification Steps

After a failover event, verify that the LDAP server has recovered:

### 1. Check Database Connectivity

```bash
# From the LDAP server host, confirm PostgreSQL is reachable
psql "postgresql://ldap_server:PASSWORD@db-host:5432/ldap_server" -c "SELECT 1;"
```

### 2. Test an LDAP Operation

```bash
# Perform a simple LDAP search to verify end-to-end operation
ldapsearch -H ldaps://ldap.example.gov:636 \
  -D "cn=test-broker,ou=brokers,dc=example,dc=gov" \
  -w "PASSWORD" \
  -b "ou=people,dc=example,dc=gov" \
  "(uid=testuser)"
```

### 3. Check Server Logs

```bash
# Look for database connection recovery messages
journalctl -u ldap-server --since "-10min" | grep -i "database\|pool\|connection"
```

### 4. Verify Pool Health

If Prometheus metrics are exposed, check:
- `db_pool_connections_active` — should be > 0.
- `db_pool_connections_idle` — should be recovering.
- `db_pool_acquire_duration_seconds` — should return to normal levels.

---

## Data Integrity Checks Post-Failover

After failover to a replica, confirm data consistency:

### 1. Verify Replication Lag Was Zero

If the failover was to a synchronous replica, data loss is unlikely. For asynchronous replicas:

```sql
-- On the new primary, check the last received LSN vs. last replayed LSN
SELECT pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn();
```

### 2. Spot-Check Identity Data

```sql
-- Verify a known identity record is present and correct
SELECT uid, display_name, updated_at
FROM identity.users
WHERE uid = 'known-test-user';
```

### 3. Verify JIT Credential State

```sql
-- Check that recently provisioned JIT credentials are intact
SELECT bind_dn, created_at, expires_at
FROM runtime.jit_credentials
ORDER BY created_at DESC
LIMIT 10;
```

### 4. Run Replication Health Check

If replication from the central authority is enabled, trigger a manual pull and confirm it succeeds without sequence gaps.

---

## Troubleshooting

| Problem | Likely Cause | Resolution |
|---------|-------------|------------|
| Pool never recovers | DNS/VIP still points to old primary | Verify DNS resolution from the LDAP server host |
| Connections succeed but queries fail | New primary is read-only (still in replica mode) | Promote the replica or check the proxy configuration |
| Intermittent errors after failover | Mixed connections to old and new primary | Restart the LDAP server to force a clean pool |
| Audit log shows persistent DB errors | Firewall or network partition | Check network connectivity and firewall rules |
