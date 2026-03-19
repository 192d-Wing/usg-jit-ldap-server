# Operational Security Guidance

This document provides operational security procedures for the USG JIT LDAP Server
at each of the 184 deployment sites. It is written for site operations teams,
security officers, and incident responders.

---

## 1. Certificate Rotation Procedures

### Server TLS Certificate (LDAPS)

The server TLS certificate secures all client-to-server LDAP communication.
Certificate expiry causes service failure (fail-closed design).

**Rotation Steps:**

1. **Obtain new certificate** from the project PKI/CA at least 30 days before
   expiry. The new certificate must:
   - Match the server's hostname/FQDN
   - Use a key size of at least 2048 bits (RSA) or 256 bits (ECDSA)
   - Include the full chain to the trusted root CA
   - Have a validity period consistent with organizational policy

2. **Validate the certificate** before deployment:
   ```bash
   openssl x509 -in new-cert.pem -text -noout   # Verify subject, issuer, dates
   openssl verify -CAfile ca-chain.pem new-cert.pem   # Verify chain
   openssl rsa -in new-key.pem -check   # Verify key integrity (RSA)
   ```

3. **Deploy the certificate** to the configured paths (`tls.cert_path`,
   `tls.key_path` in `config.toml`). Set file permissions:
   ```bash
   chmod 644 /etc/ldap-server/certs/server.pem   # Certificate (public)
   chmod 600 /etc/ldap-server/certs/server-key.pem   # Private key
   chown ldap-service:ldap-service /etc/ldap-server/certs/*
   ```

4. **Restart the service** to load the new certificate:
   ```bash
   systemctl restart ldap-server
   ```

5. **Verify** the new certificate is in use:
   ```bash
   openssl s_client -connect localhost:636 -showcerts < /dev/null 2>/dev/null \
     | openssl x509 -noout -dates -subject
   ```

6. **Monitor** for TLS errors in the audit log after rotation.

**Monitoring:**
- Set up alerting for certificates expiring within 30 days.
- Monitor `TlsError` audit events for unexpected handshake failures after rotation.
- Log the `service_started` audit event after restart; verify `tls_min_version` is correct.

### Replication Client Certificate (mTLS)

Each site presents a client certificate to the central hub during replication pulls.

**Rotation follows the same steps** as the server certificate, with additional
requirements:
- The certificate CN must match the registered site ID in the hub's site registry.
- The hub must be updated to trust the new certificate before the old one expires.
- Coordinate rotation with the central hub operations team to avoid replication
  interruption.

### Certificate Expiry Calendar

Maintain a centralized certificate inventory tracking:
- Certificate subject and issuer
- Serial number
- Not-before and not-after dates
- Deployment location (site code, file path)
- Rotation schedule

---

## 2. Password / Credential Lifecycle

### Ephemeral Password Lifecycle

Ephemeral passwords follow this lifecycle:

```
Issued by JIT Broker -> Active (usable for Bind) -> Expired (TTL elapsed)
                                                  -> Used (single-use flag)
                                                  -> Revoked (admin action)
```

**Operational Procedures:**

| Action | How | Who |
|---|---|---|
| Issue credential | JIT Broker invokes Password Modify ExtOp or direct DB API | Broker service |
| Verify credential | User Binds; server checks hash, TTL, used, revoked flags | Automatic |
| Expire credential | TTL elapses; Bind verification rejects expired credentials | Automatic |
| Revoke credential | Set `revoked = TRUE` in `runtime.ephemeral_passwords` | Site admin or Broker |
| Clean up expired | Scheduled job deletes expired rows (see below) | Maintenance cron |

**Cleanup Job:**

Run periodically (recommended: every 6 hours) to remove expired credentials:
```sql
DELETE FROM runtime.ephemeral_passwords
WHERE expires_at < now() - interval '24 hours';
```

Retain expired credentials for 24 hours after expiry to support forensic analysis
of recent authentication attempts.

### Database Service Credentials

The LDAP server connects to PostgreSQL using a service account. Rotation:

1. Create a new PostgreSQL role with identical permissions.
2. Update `database.url` in `config.toml` with the new credentials.
3. Restart the service.
4. Verify connectivity (check for database errors in logs).
5. Drop the old role after confirming the new one is working.

Do NOT use the PostgreSQL superuser role for the LDAP service.

---

## 3. Monitoring and Alerting Recommendations

### Key Metrics to Monitor

| Metric | Source | Alert Threshold | Severity |
|---|---|---|---|
| Bind failure rate | `bind_attempt` audit events | >50 failures/5 min | HIGH |
| Rate limit trigger count | `rate_limit_triggered` events | >20 triggers/5 min | MEDIUM |
| Active connections | Process metrics | >80% of `max_connections` | HIGH |
| Replication sync age | `replication_metadata.last_sync_at` | >2x `stale_threshold_secs` | HIGH |
| Audit queue depth | `runtime.audit_queue` row count (forwarded=FALSE) | >10,000 rows | HIGH |
| TLS handshake failure rate | `tls_error` events | >10/min from single IP | MEDIUM |
| Database connection pool utilization | Pool metrics | >80% utilization | MEDIUM |
| Certificate days-to-expiry | External monitoring | <30 days | HIGH |
| Service restarts | `service_started` events | Unexpected restart | MEDIUM |
| Replication consecutive failures | Health monitoring | >10 consecutive | HIGH |

### Health Check Endpoints

The service should expose (or a sidecar should provide):

- **Liveness:** Process is running and accepting TCP connections on port 636.
- **Readiness:** TLS handshake succeeds AND database connection is healthy AND
  (if replication is enabled) replication data is not stale.

### SIEM Integration

Forward audit events from `runtime.audit_queue` to the organizational SIEM.
See the [Audit Strategy](audit-strategy.md) for detailed forwarding architecture,
alert rules, and review schedules.

---

## 4. Incident Response Integration Points

### Detection Sources

The LDAP server provides the following data for incident detection:

| Data Source | Location | IR Use |
|---|---|---|
| Bind attempt events | `runtime.audit_queue` + SIEM | Detect credential attacks |
| Search request events | `runtime.audit_queue` + SIEM | Detect data exfiltration |
| Rate limit triggers | `runtime.audit_queue` + SIEM | Detect brute force |
| TLS error events | `runtime.audit_queue` + SIEM | Detect protocol attacks |
| Connection logs | `runtime.audit_queue` + SIEM | Reconstruct session timeline |
| Replication health | `runtime.health_state` | Detect data integrity issues |

### Incident Response Actions

| Scenario | Immediate Action | LDAP Server Steps |
|---|---|---|
| Compromised user credential | Revoke credential | `UPDATE runtime.ephemeral_passwords SET revoked = TRUE WHERE user_id = (SELECT id FROM identity.users WHERE dn = $1)` |
| Brute force attack in progress | Block source IP | Network firewall rule; rate limiter provides time |
| Suspected data exfiltration | Review search logs | Query `runtime.audit_queue` for `search_*` events from suspect DN |
| Compromised JIT Broker | Disable broker DN | Remove from `broker_dns` in config; restart service |
| Compromised site | Isolate site network | Revoke site replication certificate at hub |
| Replication poisoning | Halt replication | Disable replication in config; restart; investigate at hub |
| Certificate compromise | Replace certificate | Follow rotation procedure; revoke old cert at CA |

### Forensic Data Preservation

During an incident, preserve the following before any cleanup:
1. `runtime.audit_queue` — full table export
2. `runtime.bind_events` — full table export
3. `runtime.ephemeral_passwords` — full table export (hashes, not plaintext)
4. Service logs (stdout/stderr as captured by supervisor)
5. PostgreSQL logs
6. Network flow data from site firewall

---

## 5. Backup and Recovery

### What to Back Up

| Data | Back Up? | Rationale |
|---|---|---|
| `identity` schema | Yes (but recoverable from hub) | Speeds recovery; avoids full re-sync |
| `runtime.ephemeral_passwords` | NO | Ephemeral by design; re-issuance is the recovery path |
| `runtime.bind_events` | Yes | Forensic value |
| `runtime.audit_queue` | Yes | Compliance requirement; forensic value |
| `runtime.rate_limit_state` | No | Operational state; rebuilds automatically |
| `runtime.health_state` | No | Operational state; rebuilds automatically |
| `config.toml` | Yes | Configuration management; version-controlled |
| TLS certificates | Yes (secure backup) | Required for service restart |
| TLS private keys | Yes (encrypted, offline) | Required for service restart |

### Recovery Procedures

**Scenario: Site database loss (full rebuild)**
1. Provision a new PostgreSQL instance.
2. Run migrations (`00001_identity_schema.sql`, `00002_runtime_schema.sql`).
3. Configure and start the replication puller — identity data will sync from hub.
4. Restore `runtime.audit_queue` and `runtime.bind_events` from backup (if available).
5. JIT Broker re-issues credentials as needed — no need to restore passwords.
6. Start the LDAP service.

**Scenario: Service process failure**
1. The process supervisor (systemd, container orchestrator) restarts the service.
2. Verify the `service_started` audit event indicates successful startup.
3. Verify TLS and database connectivity in the logs.
4. No data is lost — all state is in PostgreSQL.

**Scenario: TLS certificate loss**
1. Restore certificate and key from secure backup, or request re-issuance from CA.
2. Deploy to configured paths with correct permissions.
3. Restart the service.

### Backup Schedule

| Item | Frequency | Retention | Method |
|---|---|---|---|
| Full database dump | Daily | 30 days | `pg_dump` with encryption |
| WAL archiving | Continuous | 7 days | PostgreSQL WAL archival |
| Configuration files | On change | Version controlled | Git or config management |
| TLS certificates | On rotation | Until successor verified | Encrypted offline storage |

---

## 6. Patch Management

### Application Dependencies

1. **Monitor** for security advisories in dependencies:
   ```bash
   cargo audit   # Run weekly or in CI
   ```

2. **Update** dependencies on a regular schedule (monthly) and immediately for
   security-critical vulnerabilities:
   ```bash
   cargo update
   cargo audit
   cargo test
   ```

3. **Critical dependencies** requiring immediate patching if vulnerabilities
   are disclosed:
   - `rustls` — TLS implementation
   - `ring` — cryptographic primitives
   - `argon2` — password hashing
   - `sqlx` — database driver
   - `tokio` — async runtime

4. **Test** after updates: run the full test suite and verify TLS handshake,
   Bind, Search, and audit logging work correctly.

### Operating System and PostgreSQL

| Component | Patch Cadence | Testing Required |
|---|---|---|
| OS security patches | Within 30 days (14 for critical) | Basic service health check |
| PostgreSQL minor versions | Within 30 days | Full functional test |
| PostgreSQL major versions | Planned upgrade with testing | Full regression test |
| Rust toolchain | Quarterly | Full build and test |

---

## 7. Log Management and Retention

### Log Sources

| Source | Format | Destination | Retention |
|---|---|---|---|
| Service stdout/stderr | JSON (tracing) | Process supervisor log capture | 30 days local |
| `runtime.audit_queue` | JSONB | Local PostgreSQL + SIEM forwarding | 7 days local (forwarded), 30 days (un-forwarded) |
| `runtime.bind_events` | Relational | Local PostgreSQL | 90 days |
| PostgreSQL server logs | Text | Local filesystem | 30 days |

### Log Rotation

- Service logs: handled by the process supervisor (journald, Docker, etc.)
- Database logs: configure `log_rotation_age` and `log_rotation_size` in
  `postgresql.conf`
- Audit queue: cleaned by scheduled maintenance job (see Retention below)

### Retention Enforcement

Run the following cleanup job daily (via cron or pg_cron):

```sql
-- Remove forwarded audit events older than 7 days
DELETE FROM runtime.audit_queue
WHERE forwarded = TRUE AND forwarded_at < now() - interval '7 days';

-- Remove old bind events (90-day retention)
DELETE FROM runtime.bind_events
WHERE attempted_at < now() - interval '90 days';

-- Remove expired rate limit state (24-hour retention)
DELETE FROM runtime.rate_limit_state
WHERE window_start < now() - interval '24 hours';

-- VACUUM after bulk deletes
VACUUM ANALYZE runtime.audit_queue;
VACUUM ANALYZE runtime.bind_events;
VACUUM ANALYZE runtime.rate_limit_state;
```

### Log Protection

- The LDAP service database role has INSERT-only access to `audit_queue` (no
  DELETE or UPDATE).
- Cleanup is performed by a separate maintenance role with restricted DELETE
  permissions.
- Forwarded events are stored in the central SIEM beyond the local admin's
  control.

---

## 8. Access Control for Administrative Functions

### Database Access Roles

| Role | Permissions | Holder |
|---|---|---|
| `ldap_service` | SELECT on `identity.*`; SELECT, INSERT on `runtime.bind_events`, `runtime.audit_queue`, `runtime.rate_limit_state`, `runtime.health_state`; SELECT on `runtime.ephemeral_passwords` | LDAP server process |
| `jit_broker` | INSERT, UPDATE on `runtime.ephemeral_passwords` | JIT Broker service |
| `replication_puller` | INSERT, UPDATE, DELETE on `identity.*`; SELECT, UPDATE on `identity.replication_metadata` | Replication puller |
| `maintenance` | DELETE on `runtime.audit_queue`, `runtime.bind_events`, `runtime.rate_limit_state`; VACUUM | Scheduled maintenance job |
| `readonly_audit` | SELECT on `runtime.audit_queue`, `runtime.bind_events` | Incident response, compliance review |
| `pg_admin` | Superuser | DBA (break-glass only) |

### Administrative Access Controls

1. **No direct database access** for routine operations. All LDAP operations go
   through the service.

2. **Break-glass procedure** for DBA access:
   - Requires documented justification
   - Session logged (PostgreSQL `log_statement = 'all'`)
   - Time-limited (revoke elevated access after task completion)
   - Review by security officer within 24 hours

3. **Configuration changes** require:
   - Change request with justification
   - Peer review of `config.toml` changes
   - Service restart (no runtime reconfiguration of security settings)
   - Verification of `config_loaded` audit event with expected parameters

4. **Certificate management** requires:
   - Access to the certificate file paths on the server filesystem
   - Follows the certificate rotation procedure documented above
   - Coordinated with the PKI team for issuance/revocation

### Separation of Duties

| Function | Role | Cannot Also |
|---|---|---|
| Operate LDAP service | Site operator | Manage identities centrally |
| Issue ephemeral credentials | JIT Broker | Modify identity data |
| Manage identity data | Central IAM team | Access credential material |
| Review audit logs | Security officer | Modify audit records |
| Perform maintenance cleanup | Maintenance role | Issue credentials or modify identities |
