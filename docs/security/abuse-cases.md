# Abuse Case Analysis: USG JIT LDAP Server

This document presents detailed abuse cases for the USG JIT LDAP Server. Each case
describes an attack vector, assesses impact and likelihood, identifies mitigations
and detection mechanisms, and maps to NIST SP 800-53 Rev. 5 controls.

These abuse cases are written for ATO assessors, penetration testers, and the
implementation team. They should be used alongside the
[Threat Model](../../docs/architecture/threat-model.md) (STRIDE analysis) and
[Security Invariants](../../docs/architecture/security-invariants.md).

---

## AC-01: Credential Stuffing Attack

**Attack Vector:** An adversary uses automated tooling to submit large volumes of
Bind requests using credential lists obtained from breaches of unrelated systems.
The goal is to find valid DN/password combinations for users who reuse passwords.

**Impact:** HIGH — Successful authentication grants access to directory data. In a
JIT environment, this is partially mitigated because passwords are ephemeral and
not user-chosen, but the attack still consumes resources and generates noise.

**Likelihood:** HIGH — Credential stuffing is a routine, automated attack that
targets any exposed authentication endpoint.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Per-DN rate limiting | Sliding window counter checked before hash computation | `src/auth/rate_limit.rs` |
| 2 | Ephemeral passwords | JIT-issued, not user-chosen; not reusable across breaches | `runtime.ephemeral_passwords` |
| 3 | Password TTL | Credentials expire after configurable TTL (default 8h) | `src/config.rs` — `password_ttl_secs` |
| 4 | Constant-time response | Same error message for "user not found" and "wrong password" | `src/ldap/bind.rs` — `InvalidCredentials` for both |
| 5 | Audit logging | All Bind attempts logged with source IP, DN, and outcome | `src/audit/events.rs` — `BindAttempt` |

**Detection:**
- SIEM alert on high-volume Bind failures from a single source IP
- SIEM alert on Bind failures across many DNs from a single source IP (spray pattern)
- Rate limit trigger events (`RateLimitTriggered` audit events)
- Anomaly detection on Bind failure rates exceeding historical baseline

**NIST Controls:** AC-7, AU-2, AU-6, IA-5, SI-4

---

## AC-02: Stolen JIT Credential Replay

**Attack Vector:** An adversary obtains a valid ephemeral password (e.g., via
shoulder surfing, clipboard capture, or compromise of the system where the JIT
credential was delivered) and replays it to authenticate.

**Impact:** HIGH — Valid credential grants access to the target user's directory
data and any systems that rely on this LDAP for authentication.

**Likelihood:** MEDIUM — Requires access to the credential delivery channel. The
JIT model reduces the window of opportunity compared to persistent passwords.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | TTL enforcement | Ephemeral passwords expire after configurable TTL | `runtime.ephemeral_passwords.expires_at` |
| 2 | Single-use option | `used` flag prevents reuse after first successful Bind | `runtime.ephemeral_passwords.used` |
| 3 | Revocation | Broker or admin can set `revoked = TRUE` to invalidate immediately | `runtime.ephemeral_passwords.revoked` |
| 4 | TLS transport | Password cannot be captured from the wire (encrypted in transit) | `src/tls.rs` |
| 5 | Audit trail | Successful Bind logged with source IP; duplicate use detectable | `src/audit/events.rs` |

**Detection:**
- Alert on successful Bind from an unexpected source IP for a given DN
- Alert on Bind attempt after credential has been marked `used`
- Correlation of Bind events with JIT issuance events (issuance time vs. Bind time)
- Alert on Bind from geographic location inconsistent with the user's site assignment

**NIST Controls:** IA-5, IA-11, AU-2, AU-6, SC-8

---

## AC-03: Insider Threat (Site Administrator)

**Attack Vector:** A site administrator with local database access or operating
system privileges attempts to:
- Extract password hashes from the runtime schema
- Modify identity data to grant unauthorized access
- Tamper with or suppress audit records
- Impersonate another user

**Impact:** HIGH — Administrative access can undermine multiple controls. However,
the dual-schema design limits the blast radius.

**Likelihood:** LOW-MEDIUM — Insider threats are lower probability but high impact.
Government environments have background check and monitoring programs.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Schema separation | Identity data is replicated from central; local admin cannot create users | `identity` vs. `runtime` schemas |
| 2 | Read-only identity | LDAP service and local admin have no write access to `identity` schema | PostgreSQL role permissions |
| 3 | Audit immutability | Audit queue is append-only from LDAP service role; no DELETE permission | `runtime.audit_queue` |
| 4 | Password hashing | Hashes stored as Argon2id; raw passwords never persisted | `src/auth/password.rs` |
| 5 | Audit forwarding | Events forwarded to central SIEM beyond local admin's control | Operational SIEM integration |
| 6 | Central reconciliation | Identity data drift detected during replication sync | `src/replication/puller.rs` |

**Detection:**
- SIEM alert on direct database modifications outside normal replication/issuance
- Anomaly detection on audit event gaps (missing expected events)
- Replication reconciliation detects unauthorized identity data changes
- Privileged access monitoring at the OS level (outside LDAP scope)

**NIST Controls:** AC-2, AC-5, AC-6, AU-2, AU-9, AU-12

---

## AC-04: Replication Channel Compromise

**Attack Vector:** An adversary compromises the network path between the central
hub and a site, or compromises a site's replication credentials, to inject
malicious identity data (e.g., adding unauthorized users, modifying group
memberships, or disabling legitimate accounts).

**Impact:** HIGH — Poisoned identity data could grant unauthorized access or deny
service to legitimate users across the affected site.

**Likelihood:** LOW — Requires compromise of mutual TLS credentials or a
man-in-the-middle position on the WAN link.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Mutual TLS | Both hub and site must present valid certificates from project CA | `src/replication/puller.rs` |
| 2 | Certificate CN validation | Site certificate CN must match registered site ID | Replication authentication |
| 3 | Payload integrity | SHA-256 digest computed at hub, verified at site before applying | `src/replication/puller.rs` — `verify_entries()` |
| 3b | Protocol versioning | Site rejects entries with unsupported protocol versions | `src/replication/puller.rs` — `REPLICATION_PROTOCOL_VERSION` |
| 4 | Sequence numbers | Monotonic sequence numbers; gaps detected and logged at WARN | `src/replication/puller.rs` — `verify_entries()` |
| 5 | Change set anomaly detection | Alerts on unusually large change sets | Replication health monitoring |
| 6 | Identity-only replication | Only `identity` schema data flows; `runtime` is immune | Schema-level enforcement |

**Detection:**
- Alert on replication failure (mTLS validation failure)
- Alert on sequence number gaps or regressions
- Alert on change set size exceeding threshold
- Periodic reconciliation between hub and site data
- Certificate expiry monitoring

**NIST Controls:** IA-3, SC-8, SC-12, SI-7, AU-2

---

## AC-05: Denial of Service

**Attack Vector:** An adversary attempts to exhaust server resources through:
- TLS handshake flood (CPU exhaustion via asymmetric crypto)
- Connection exhaustion (filling the connection table)
- Bind flood (CPU exhaustion via Argon2 computation)
- Search flood (database connection / query exhaustion)
- Malformed PDU flood (parser resource consumption)

**Impact:** MEDIUM-HIGH — Service unavailability prevents authentication at the
affected site. However, each site operates independently, so the blast radius
is limited to one site per attack target.

**Likelihood:** MEDIUM — DoS is a common attack vector, though government networks
may have perimeter protections that reduce exposure.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Connection limit | Maximum concurrent connections (default: 1024) | `src/config.rs` — `max_connections` |
| 2 | Idle timeout | Connections closed after inactivity (default: 300s) | `src/config.rs` — `idle_timeout_secs` |
| 2b | Absolute session lifetime | Connections closed after 24h regardless of activity | `src/config.rs` — `max_session_lifetime_secs` |
| 3 | Rate limiting | Bind attempts throttled per DN and per source IP; rejects before hash computation | `src/auth/rate_limit.rs` |
| 4 | PDU size limit | Maximum message size prevents memory exhaustion | `src/ldap/codec.rs` |
| 5 | Search result limit | Server-enforced maximum result size (default: 1000) | `src/ldap/search.rs` — `DEFAULT_MAX_RESULT_SIZE` |
| 6 | DB connection pool | Bounded pool prevents database connection exhaustion | `src/db/pool.rs` — `max_connections` |
| 7 | TLS handshake timeout | Prevents slow-handshake attacks | Connection handler |

**Detection:**
- Monitoring of active connection count (approaching limit)
- Rate limit trigger event volume
- Database connection pool utilization metrics
- TLS handshake failure rate
- System resource metrics (CPU, memory, file descriptors)

**NIST Controls:** SC-5, AC-7, SI-4, SC-7

---

## AC-06: Data Exfiltration via Search

**Attack Vector:** An authenticated user (or attacker with stolen credentials)
performs broad Search operations to extract directory data: user lists, group
memberships, organizational structure, and email addresses.

**Impact:** MEDIUM — Directory data exposure enables further targeted attacks
(phishing, social engineering, credential correlation). Password hashes are not
exposed (different schema), limiting the direct authentication impact.

**Likelihood:** MEDIUM — Requires valid credentials (via JIT or compromise), but
Search is a normal operation that may not trigger immediate suspicion.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Bind-before-search | No anonymous Search; authentication required | `src/ldap/session.rs` — state machine |
| 2 | Result size limits | Server enforces maximum entries per Search (default: 1000) | `src/ldap/search.rs` — `max_result_size` |
| 3 | Attribute filtering | Only requested attributes returned; server-side enforcement | `src/ldap/search.rs` |
| 4 | Schema separation | Password hashes in `runtime`; Search queries only `identity` | Schema design |
| 5 | Audit logging | All Search requests and completions logged with details | `src/audit/events.rs` — `SearchRequest`, `SearchComplete` |

**Detection:**
- SIEM alert on high-volume Search operations from a single bound DN
- Alert on Search operations with unusually broad scope (subtree from root)
- Alert on Search operations requesting sensitive attributes
- Anomaly detection on Search patterns deviating from user's historical baseline
- Correlation of Search volume with user's normal access patterns

**NIST Controls:** AC-3, AC-6, AU-2, AU-6, SI-4

---

## AC-07: Password Hash Extraction

**Attack Vector:** An adversary with access to the site's PostgreSQL database
(via SQL injection, compromised DB credentials, or OS-level access) attempts to
extract Argon2id password hashes from `runtime.ephemeral_passwords`.

**Impact:** MEDIUM — Argon2id hashes are computationally expensive to crack.
Combined with short TTLs on ephemeral passwords, offline cracking is unlikely to
succeed before the credential expires. However, hash extraction represents a
significant security boundary violation.

**Likelihood:** LOW — Requires database-level access beyond what the LDAP service
provides. SQL injection is mitigated by parameterized queries.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Parameterized queries | No dynamic SQL; injection prevented | All `src/db/*.rs` modules |
| 2 | Local-only storage | Password hashes in `runtime` schema; never replicated | Schema design, replication exclusion |
| 3 | Argon2id hashing | Memory-hard KDF; resistant to GPU/ASIC cracking | `src/auth/password.rs` |
| 4 | Short TTL | Ephemeral passwords expire quickly; limits cracking window | `runtime.ephemeral_passwords.expires_at` |
| 5 | DB role separation | LDAP service role has SELECT only; cannot bulk export | PostgreSQL role permissions |
| 6 | Application zeroization | Plaintext never persisted; hashes are one-way | `src/auth/password.rs` |

**Detection:**
- Database audit logging (pg_audit) on SELECT against `runtime.ephemeral_passwords`
- Alert on unusual query patterns against runtime tables
- Alert on database connections from unexpected sources
- File integrity monitoring on PostgreSQL data directory

**NIST Controls:** IA-5, SC-28, AC-6, AU-2

---

## AC-08: Rogue JIT Broker

**Attack Vector:** An adversary compromises the JIT Broker service or its
credentials, enabling them to issue valid ephemeral passwords for any user. This
is the highest-impact compromise scenario within the trust model.

**Impact:** CRITICAL — A rogue broker can issue credentials for any DN, bypassing
all authentication controls. The blast radius is limited to the compromised site
(credentials are local-only) unless the broker has access to multiple sites.

**Likelihood:** LOW — The JIT Broker is a trusted component with its own security
controls. Compromise requires significant effort.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Broker DN authorization | Only designated DNs can invoke Password Modify | `src/config.rs` — `broker_dns` |
| 2 | TTL cap | Server enforces maximum TTL regardless of broker request | `src/config.rs` — `password_ttl_secs` |
| 3 | Audit logging | All password issuance events logged with broker identity | `src/audit/events.rs` — `PasswordModify` |
| 4 | Single-use credentials | `used` flag prevents credential reuse | `runtime.ephemeral_passwords.used` |
| 5 | Site-local scope | Issued credentials only work at the local site | Schema design |
| 6 | Issuance rate monitoring | Anomaly detection on credential issuance volume | SIEM integration |

**Detection:**
- SIEM alert on credential issuance volume exceeding historical baseline
- Alert on issuance for DNs that should not have site access
- Alert on issuance with unusually long TTLs
- Correlation of issuance events with access request system records
- Alert on broker authentication from unexpected source IP

**NIST Controls:** IA-5, IA-8, AC-2, AU-2, AU-6

---

## AC-09: Stale Identity Exploitation

**Attack Vector:** An adversary exploits a gap between identity revocation at the
central hub and propagation to the site. If a user is disabled centrally but the
site's replicated data has not yet been updated, the user may still authenticate
using an unexpired ephemeral password.

**Impact:** MEDIUM — Access persists for the duration of the replication lag (up
to the staleness threshold). Limited by the ephemeral password TTL, which may
expire before the user's access is revoked.

**Likelihood:** MEDIUM — Replication lag is inherent in the hub-and-spoke model.
The window is bounded but nonzero.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | Staleness detection | Replication health monitoring tracks sync age | `src/replication/health.rs` |
| 2 | Bounded staleness | Configurable threshold (default: 1 hour); alerts on breach | `src/config.rs` — `stale_threshold_secs` |
| 3 | Frequent pulls | Short pull interval (default: 60s) minimizes lag | `src/config.rs` — `pull_interval_secs` |
| 4 | TTL intersection | Password TTL and staleness threshold interact to limit window | Operational policy |
| 5 | User disable check | Bind verification checks `identity.users.enabled` flag | `src/db/runtime.rs` |
| 6 | Emergency revocation | Broker can revoke credentials directly in runtime schema | `runtime.ephemeral_passwords.revoked` |

**Detection:**
- Replication health monitoring alerts on stale data
- Alert on authentication by users with `enabled = FALSE` (race condition indicator)
- Monitoring of replication lag metrics per site
- Alert on replication puller failures exceeding retry threshold

**NIST Controls:** AC-2, IA-4, SI-7, CP-9

---

## AC-10: TLS Downgrade Attack

**Attack Vector:** An adversary attempts to force the connection to use weaker
TLS parameters or to bypass TLS entirely. Attack variants include:
- TLS stripping via StartTLS interception
- Protocol downgrade to TLS 1.0/1.1/1.2
- Cipher suite downgrade to non-AEAD ciphers
- Connection to a non-existent plaintext port

**Impact:** HIGH — Successful downgrade exposes credentials and directory data
in transit.

**Likelihood:** VERY LOW — The architectural design eliminates the attack surface.
There is no plaintext listener, no StartTLS implementation, and no code path that
accepts weak TLS versions.

**Mitigations:**

| # | Mitigation | Implementation | Module |
|---|---|---|---|
| 1 | No plaintext listener | Port 389 is never opened; no configuration option for it | `src/main.rs` |
| 2 | No StartTLS | Extended operation handler does not recognize StartTLS OID | `src/ldap/password.rs` |
| 3 | TLS 1.3 only | Only TLS 1.3 accepted; 1.0/1.1/1.2 not available | `src/tls.rs` — `build_server_config()` |
| 4 | AEAD-only ciphers | rustls default provider restricts to strong cipher suites | `src/tls.rs` — rustls defaults |
| 5 | Fail-closed | Server will not start without valid TLS material | `src/main.rs` — startup sequence |
| 6 | Config validation | Port must be 636 unless explicitly overridden for testing | `src/config.rs` — `validate()` |

**Detection:**
- TLS handshake failure events logged (`TlsError` audit events)
- Monitoring of TLS negotiated parameters (version, cipher) at the load balancer
- Network IDS alerts on plaintext LDAP traffic (should never exist)

**NIST Controls:** SC-7, SC-8, SC-13, SC-23, CM-7

---

## Summary Risk Matrix

| ID | Abuse Case | Impact | Likelihood | Risk | Primary Controls |
|---|---|---|---|---|---|
| AC-01 | Credential Stuffing | High | High | **High** | AC-7, IA-5, SI-4 |
| AC-02 | JIT Credential Replay | High | Medium | **High** | IA-5, SC-8, AU-2 |
| AC-03 | Insider Threat | High | Low-Med | **Medium** | AC-6, AU-9, AU-12 |
| AC-04 | Replication Compromise | High | Low | **Medium** | IA-3, SC-8, SI-7 |
| AC-05 | Denial of Service | Med-High | Medium | **Medium** | SC-5, AC-7, SI-4 |
| AC-06 | Search Exfiltration | Medium | Medium | **Medium** | AC-3, AU-2, SI-4 |
| AC-07 | Hash Extraction | Medium | Low | **Low-Med** | IA-5, SC-28, AC-6 |
| AC-08 | Rogue Broker | Critical | Low | **Medium** | IA-5, AC-2, AU-2 |
| AC-09 | Stale Identity | Medium | Medium | **Medium** | AC-2, SI-7, CP-9 |
| AC-10 | TLS Downgrade | High | Very Low | **Low** | SC-8, SC-13, CM-7 |
