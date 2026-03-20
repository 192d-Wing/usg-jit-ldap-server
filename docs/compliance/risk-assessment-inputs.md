# Risk Assessment Inputs

This document summarizes the threat model, residual risks, mitigations, and
compensating controls for the USG JIT LDAP Server. It is intended as input to
the formal Risk Assessment required for ATO.

For the full threat model, see
[../architecture/threat-model.md](../architecture/threat-model.md).

---

## 1. Threat Model Summary

The threat model uses the STRIDE methodology applied to each major component
and trust boundary. The analysis covers six components:

| Component | Key Threats | Primary Mitigations |
|-----------|-------------|---------------------|
| **LDAPS Listener** (`src/tls.rs`) | TLS downgrade (T-L4), handshake flood (T-L5), certificate spoofing (T-L1) | TLS 1.2+ only, no plaintext, connection rate limiting, rustls (pure-Rust, audited) |
| **Session Handler** (`src/ldap/session.rs`) | State confusion (T-S6), unauthenticated data access (T-S4), malformed PDU (T-S2) | Rust enum state machine with exhaustive match, Bind-before-Search enforcement, strict BER parser with size limits |
| **Bind Handler** (`src/ldap/bind.rs`) | Credential stuffing (T-B1), timing side-channel (T-B3), password leak from memory (T-B4) | Per-DN/IP rate limiting, constant-time hash comparison, zeroize crate for password material |
| **Search Handler** (`src/ldap/search.rs`) | Data exfiltration (T-Q1), enumeration (T-Q3), complex filter DoS (T-Q2) | Schema-level attribute filtering, size limits, filter depth limits, all searches audited |
| **PostgreSQL Backend** (`src/db/`) | SQL injection (T-D1), privilege escalation (T-D3), cross-schema data leak (T-D2) | Parameterized queries only, role-based access control, dual-schema separation |
| **Replication Puller** (`src/replication/`) | Hub impersonation (T-R1), payload tampering (T-R2), credential exfiltration (T-R3) | Mutual TLS, SHA-256 integrity digests, sequence numbers, identity-only replication |

### Attack Vectors Analyzed

Seven specific attack vectors are analyzed in the threat model with layered
mitigations:

1. **Credential Stuffing** — Rate limiting, ephemeral passwords, audit detection
2. **Replay Attack** — TLS prevents capture; ephemeral TTLs limit window
3. **Man-in-the-Middle** — LDAPS-only (no StartTLS stripping), certificate validation
4. **Data Exfiltration** — Bind-before-Search, size limits, schema separation
5. **Insider Threat** — Append-only audit, hashed credentials, role separation
6. **Denial of Service** — Connection limits, rate limiting, query timeouts
7. **Replication Poisoning** — mTLS, integrity digests, anomaly detection

---

## 2. Residual Risks

After all implemented mitigations, the following residual risks remain:

### R-1: Compromised JIT Broker (HIGH)

**Description:** If the JIT Broker is compromised, an attacker can issue valid
ephemeral passwords for any user within the configured TTL window.

**Current Mitigations:**
- Password TTL limits the window of validity (default: 8 hours)
- All password issuance is audit-logged with broker identity and target DN
- Broker DN must be explicitly configured in `security.broker_dns`
- Single-use password flag limits reuse

**Residual Risk:** An attacker with broker credentials can authenticate as any
user for up to the TTL duration. Detection depends on audit log monitoring.

**Risk Level:** High (impact) / Low (likelihood if broker is properly secured)

### R-2: Stale Replication Data (MEDIUM)

**Description:** If replication from the central hub fails for an extended
period, site-local identity data becomes stale. Disabled accounts may remain
active, and new accounts may not be available.

**Current Mitigations:**
- Replication health monitoring with staleness detection
- Configurable staleness thresholds
- Operational alerts on sync failure
- Sites continue to operate with last-known-good data

**Residual Risk:** A disabled user could continue to authenticate at a site
with stale data until replication resumes and the disable propagates.

**Risk Level:** Medium

### R-3: NTP Desynchronization (LOW)

**Description:** Password TTL enforcement and audit timestamp accuracy depend
on host clock accuracy. Significant clock skew could extend password validity
or create gaps in audit timelines.

**Current Mitigations:**
- TTL enforcement uses server-side UTC timestamps
- Operational documentation requires NTP configuration
- Database `created_at` provides secondary timestamp

**Residual Risk:** Clock skew of minutes could extend or reduce effective
password TTL by the same amount.

**Risk Level:** Low

### R-4: Dependency Vulnerability (LOW)

**Description:** A vulnerability in a Rust dependency (rustls, argon2, sqlx,
tokio) could undermine specific controls.

**Current Mitigations:**
- Minimal dependency set (ADR-006)
- `cargo audit` for known vulnerability scanning
- `cargo deny` for license and advisory policy enforcement
- Pure-Rust TLS implementation (rustls) avoids C memory safety issues

**Residual Risk:** Zero-day vulnerabilities in dependencies before advisory
publication.

**Risk Level:** Low

### R-5: Audit Log Tampering at Database Level (LOW)

**Description:** An attacker with PostgreSQL administrative access could modify
or delete audit records in `runtime.audit_queue`.

**Current Mitigations:**
- LDAP service role has INSERT-only on audit tables (no UPDATE/DELETE)
- Audit events are also emitted via tracing (stdout) for independent capture
- SIEM forwarding provides an off-host copy of audit data

**Residual Risk:** A compromised database administrator could tamper with
on-host audit records. Off-host SIEM copies provide compensating detection.

**Risk Level:** Low

### R-6: TLS Library Vulnerability (LOW)

**Description:** A vulnerability in rustls or ring could compromise transport
confidentiality or integrity.

**Current Mitigations:**
- rustls is a pure-Rust, formally audited TLS implementation
- ring is a widely reviewed cryptographic library
- Both are actively maintained with rapid security response
- `cargo audit` detects known advisories

**Residual Risk:** Zero-day in TLS stack before patch availability.

**Risk Level:** Low

---

## 3. Risk Acceptance Recommendations

| Risk | Recommendation | Rationale |
|------|---------------|-----------|
| R-1 (Broker Compromise) | **Accept with monitoring** | TTL enforcement and audit logging provide detection and bounded impact. Broker security is the primary mitigation and is outside the LDAP server boundary. |
| R-2 (Stale Replication) | **Accept with operational controls** | Replication health monitoring and alerting provide timely detection. The staleness window is bounded by the monitoring threshold. |
| R-3 (NTP Desynchronization) | **Accept** | Standard operational practice (NTP) mitigates this. Impact is proportional to clock skew, which is typically sub-second with NTP. |
| R-4 (Dependency Vulnerability) | **Accept with continuous monitoring** | `cargo audit` in CI pipeline provides timely detection. Minimal dependency set limits exposure. |
| R-5 (Audit Tampering) | **Accept with compensating control** | SIEM forwarding provides tamper-evident off-host copies. Database admin access should be separately controlled. |
| R-6 (TLS Vulnerability) | **Accept** | Using the most reviewed and audited Rust TLS stack available. Rapid patching process documented. |

---

## 4. Compensating Controls

### For R-1 (Broker Compromise)

- **Detect:** SIEM alert rule on unusual password issuance volume or unusual
  target DNs from broker identity
- **Contain:** Broker DN can be removed from `security.broker_dns` to
  immediately revoke issuance capability (requires config reload / restart)
- **Recover:** All ephemeral passwords have bounded TTLs; compromise impact is
  self-healing after the TTL window expires

### For R-2 (Stale Replication)

- **Detect:** Replication health endpoint reports staleness; monitoring alerts
  on threshold breach
- **Contain:** Operational decision to reduce password TTLs during extended
  replication outage
- **Recover:** Replication recovery runbook provides re-sync procedures
  (`docs/operations/replication-recovery.md`)

### For R-5 (Audit Tampering)

- **Detect:** SIEM gap detection identifies missing events compared to expected
  volume
- **Contain:** SIEM retains independent copy; database forensics can identify
  tampering via PostgreSQL WAL analysis
- **Prevent:** Database admin access should require MFA and be separately audited

---

## 5. Assumptions

The risk assessment assumes the following conditions are met:

1. The JIT Broker is not compromised and follows secure credential issuance
   practices
2. TLS as implemented by rustls provides confidentiality and integrity
3. The host operating system is hardened per site infrastructure baselines
4. PostgreSQL access controls are correctly configured (roles, permissions)
5. Host clocks are approximately synchronized via NTP or equivalent
6. PKI certificate authority is operated securely
7. Physical security at each site prevents unauthorized hardware access

See the full assumptions list in
[../architecture/threat-model.md](../architecture/threat-model.md).
