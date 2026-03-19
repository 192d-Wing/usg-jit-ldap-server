# Implementation Phases with Security Milestones

This document defines the phased implementation plan for the USG JIT LDAP Server,
with explicit security milestones and acceptance criteria at each phase. Each phase
builds on the previous one, and no phase can begin until its predecessor's security
criteria are met.

---

## Phase 1: Foundation (Security-Critical)

**Objective:** Establish the security-critical foundation that all subsequent
phases depend on. Every line of code in this phase is security-relevant.

### Deliverables

| Component | Module | Description |
|---|---|---|
| TLS listener | `src/tls.rs`, `src/main.rs` | LDAPS listener on port 636 with fail-closed behavior |
| Configuration | `src/config.rs` | TOML config loading with security-critical validation |
| Database connection | `src/db/pool.rs` | PostgreSQL connection pool with role-based access |
| Schema separation | `migrations/00001_*.sql`, `00002_*.sql` | Identity and runtime schemas with access controls |
| Audit framework | `src/audit/mod.rs`, `src/audit/events.rs` | Structured audit event emission (at minimum via tracing) |

### Security Milestones

- [ ] **SM-1.1:** Server refuses to start if TLS certificate is missing, corrupted,
  or expired. Verified by test: remove cert file, attempt start, confirm exit code != 0.
- [ ] **SM-1.2:** No code path exists that accepts a plaintext TCP connection for
  LDAP processing. Verified by code review: all LDAP handling occurs after
  `tls_acceptor.accept()`.
- [ ] **SM-1.3:** TLS minimum version is 1.2. Verified by test: attempt connection
  with TLS 1.0/1.1, confirm rejection.
- [ ] **SM-1.4:** Configuration validator rejects port != 636 without explicit
  override. Verified by unit test.
- [ ] **SM-1.5:** Database connection uses a least-privilege role. Verified by
  attempting a write to `identity` schema from the LDAP service role, confirm failure.
- [ ] **SM-1.6:** `identity` and `runtime` schemas are created with proper
  separation. Verified by migration review.
- [ ] **SM-1.7:** Service lifecycle audit events (`config_loaded`, `service_started`,
  `service_stopped`) are emitted. Verified by log inspection during startup/shutdown.

### NIST Controls Activated

SC-8, SC-13, SC-17, CM-6, CM-7, AU-2 (partial), AU-12 (partial)

### Acceptance Criteria

All SM-1.x milestones pass. Security code review completed using the
[Code Review Checklist](code-review-checklist.md) sections 1, 2, 9, and 10.

---

## Phase 2: Core Operations

**Objective:** Implement the primary LDAP operations (Bind and Search) with full
security controls: authentication, rate limiting, access enforcement, and audit
logging.

### Deliverables

| Component | Module | Description |
|---|---|---|
| BER codec | `src/ldap/codec.rs` | Strict BER/ASN.1 parser with size limits |
| Session state machine | `src/ldap/session.rs` | Per-connection state: Connected -> Bound -> Closed |
| Bind handler | `src/ldap/bind.rs` | LDAPv3 Simple Bind with authentication delegation |
| Password verification | `src/auth/password.rs` | Argon2id hashing and verification with zeroization |
| Rate limiter | `src/auth/rate_limit.rs` | Per-DN sliding window rate limiting |
| Search handler | `src/ldap/search.rs` | Search with bind-before-search and result size limits |
| Database repositories | `src/db/identity.rs`, `src/db/runtime.rs` | Parameterized queries for identity and runtime data |
| Complete audit events | `src/audit/events.rs` | All operation-level audit events |

### Security Milestones

- [ ] **SM-2.1:** Anonymous Binds (empty DN or empty password) are rejected.
  Verified by test: send Bind with empty DN, confirm `InvalidCredentials`.
- [ ] **SM-2.2:** SASL Binds are rejected with `authMethodNotSupported`. Verified
  by test.
- [ ] **SM-2.3:** Rate limiter is checked BEFORE password hash retrieval. Verified
  by code review and by test: exceed rate limit, confirm no Argon2 computation
  occurs (observable via timing or log inspection).
- [ ] **SM-2.4:** Password bytes are zeroized after `verify_password()` returns.
  Verified by code review of `src/auth/password.rs`.
- [ ] **SM-2.5:** `hash_password()` zeroizes input plaintext after hashing.
  Verified by code review.
- [ ] **SM-2.6:** Search is rejected for sessions not in the `Bound` state.
  Verified by test: send Search without prior Bind, confirm rejection.
- [ ] **SM-2.7:** Search result size is capped by server-side `max_result_size`
  regardless of client-requested `sizeLimit`. Verified by test.
- [ ] **SM-2.8:** All SQL queries use parameterized statements. Verified by
  `grep` for string formatting in `src/db/` — no dynamic SQL.
- [ ] **SM-2.9:** BER codec rejects malformed input without panic. Verified by
  fuzz-like test with random byte sequences.
- [ ] **SM-2.10:** "User not found" and "wrong password" produce identical client
  responses (`InvalidCredentials`). Verified by test.
- [ ] **SM-2.11:** Every Bind attempt, Search request, and Search completion
  produces an audit event. Verified by integration test.
- [ ] **SM-2.12:** No audit event contains password bytes or hashes. Verified by
  review of `AuditEvent` struct definitions.

### NIST Controls Activated

IA-2, IA-5, IA-5(1), AC-3, AC-7, AC-14, SC-23, SI-10, AU-2, AU-3, AU-8, AU-12

### Acceptance Criteria

All SM-2.x milestones pass. Full security code review using all sections of the
[Code Review Checklist](code-review-checklist.md). Unit and integration test
coverage for all security-critical paths.

---

## Phase 3: Integration

**Objective:** Integrate the replication puller, Password Modify extended operation,
and broker authorization. Establish the end-to-end audit flow from operation to
database persistence.

### Deliverables

| Component | Module | Description |
|---|---|---|
| Replication puller | `src/replication/puller.rs` | Pull identity data from central hub with mTLS |
| Replication health | `src/replication/health.rs` | Staleness detection and health monitoring |
| Password Modify | `src/ldap/password.rs` | Extended operation for broker credential issuance |
| Broker authorization | `src/auth/mod.rs` | DN-based authorization for Password Modify |
| Audit persistence | `src/audit/mod.rs` | Database-backed audit logging to `runtime.audit_queue` |

### Security Milestones

- [ ] **SM-3.1:** Replication puller connects to hub using mutual TLS. Verified
  by test: attempt connection without client certificate, confirm rejection.
- [ ] **SM-3.2:** Replication queries ONLY the `identity` schema. Verified by
  code review and by test: confirm no data from `runtime` appears in replication
  payloads.
- [ ] **SM-3.3:** Replication payload integrity is verified (SHA-256 digest).
  Verified by test: tamper with payload, confirm rejection.
- [ ] **SM-3.4:** Sequence number gaps are detected. Verified by test: skip a
  sequence number, confirm alert.
- [ ] **SM-3.5:** Password Modify is only accepted from authorized broker DNs.
  Verified by test: attempt from non-broker DN, confirm rejection.
- [ ] **SM-3.6:** Issued passwords have server-enforced TTL cap. Verified by test:
  request TTL > max, confirm cap is applied.
- [ ] **SM-3.7:** All Password Modify operations produce audit events with broker
  identity and target DN. Verified by test.
- [ ] **SM-3.8:** Audit events are persisted to `runtime.audit_queue`. Verified
  by test: perform operation, query `audit_queue`, confirm event present.
- [ ] **SM-3.9:** Audit logging failure does not crash the service or block the
  LDAP operation. Verified by test: simulate database write failure, confirm
  operation succeeds and tracing output still emits the event.
- [ ] **SM-3.10:** Staleness detection alerts when replication data exceeds the
  configured age threshold. Verified by test.

### NIST Controls Activated

IA-3, IA-8, SC-8 (replication), SC-12, SI-7, CP-9, AU-4, AU-5, AU-9

### Acceptance Criteria

All SM-3.x milestones pass. End-to-end integration test covering:
Bind -> Search -> Password Modify -> Audit queue persistence -> Replication pull.
Security code review of replication and broker authorization paths.

---

## Phase 4: Hardening

**Objective:** Validate security properties through adversarial testing. Identify
and remediate vulnerabilities before production deployment.

### Activities

| Activity | Description | Deliverable |
|---|---|---|
| Penetration testing | External security assessment against running service | Pentest report with findings |
| BER codec fuzzing | AFL/libfuzzer against `decode_frame()` | Fuzz corpus and findings report |
| Rate limiter stress test | Verify rate limiting under concurrent load | Performance report |
| TLS configuration audit | Verify cipher suites, protocol versions with testssl.sh | TLS audit report |
| Dependency audit | `cargo audit` + manual review of critical deps | Audit report |
| Error message review | Verify no sensitive data in client-facing errors | Review signoff |
| Timing analysis | Verify constant-time behavior for authentication | Timing analysis report |
| Resource exhaustion testing | Connection floods, large PDUs, query storms | Capacity report |

### Security Milestones

- [ ] **SM-4.1:** Penetration test completed with no critical or high findings
  unresolved.
- [ ] **SM-4.2:** BER codec fuzz testing completed with no panics or memory safety
  issues found. Minimum: 1 million iterations.
- [ ] **SM-4.3:** Rate limiter correctly limits under concurrent load (100+
  simultaneous Bind attempts from different sources). No bypass possible.
- [ ] **SM-4.4:** `testssl.sh` scan shows no weak ciphers, no protocol versions
  below 1.2, no known TLS vulnerabilities.
- [ ] **SM-4.5:** `cargo audit` reports zero known vulnerabilities.
- [ ] **SM-4.6:** No `unsafe` blocks in application code (verified by automated scan).
- [ ] **SM-4.7:** All error messages reviewed for information leakage. No internal
  paths, stack traces, or database details exposed to clients.
- [ ] **SM-4.8:** Staleness and failure mode testing completed per the
  [Failure Modes](../../docs/replication/failure-modes.md) document.

### NIST Controls Validated

All previously activated controls are validated through adversarial testing.

### Acceptance Criteria

All SM-4.x milestones pass. Penetration test report reviewed and all findings
addressed. ATO documentation package drafted.

---

## Phase 5: Operational Readiness

**Objective:** Prepare for production deployment with monitoring, alerting,
operational procedures, and the final ATO documentation package.

### Activities

| Activity | Description | Deliverable |
|---|---|---|
| Monitoring integration | Deploy metrics exporters and SIEM forwarder | Monitoring runbook |
| Alert configuration | Implement SIEM alert rules per [Audit Strategy](audit-strategy.md) | Alert rule definitions |
| Runbook creation | Operational procedures for common scenarios | Site operations runbook |
| Certificate automation | Automated certificate renewal and deployment | Cert management playbook |
| Deployment pipeline | Hardened CI/CD with security gates | Pipeline configuration |
| ATO package assembly | Final compliance documentation package | ATO submission package |

### Security Milestones

- [ ] **SM-5.1:** SIEM forwarder deployed and verified: events appear in central
  SIEM within 5 minutes of occurrence.
- [ ] **SM-5.2:** All SIEM alert rules from the [Audit Strategy](audit-strategy.md)
  are configured and tested with synthetic events.
- [ ] **SM-5.3:** Certificate expiry monitoring is active for all sites; alerts
  fire at 30, 14, and 7 days before expiry.
- [ ] **SM-5.4:** Runbook covers: certificate rotation, credential revocation,
  replication failure, service restart, incident response.
- [ ] **SM-5.5:** CI/CD pipeline includes: `cargo test`, `cargo audit`,
  `cargo clippy`, SAST scan, container image scan (if containerized).
- [ ] **SM-5.6:** ATO package includes:
  - System Security Plan (SSP)
  - This NIST control mapping
  - Penetration test report
  - Code review checklist (signed)
  - Operational security guide
  - Threat model and abuse cases
  - Security architecture diagrams
- [ ] **SM-5.7:** Disaster recovery test completed: full site rebuild from scratch,
  verify service operational within defined RTO.
- [ ] **SM-5.8:** Tabletop incident response exercise completed covering at least
  three scenarios from the [Abuse Cases](abuse-cases.md) document.

### Acceptance Criteria

All SM-5.x milestones pass. ATO package submitted and accepted by assessors.
All 184 sites can be deployed from a reproducible, audited pipeline.

---

## Phase Summary

| Phase | Focus | Key Security Outcome | NIST Families |
|---|---|---|---|
| 1 | Foundation | TLS enforcement, fail-closed, schema separation | SC, CM |
| 2 | Core Operations | Authentication, rate limiting, audit logging | IA, AC, AU, SI |
| 3 | Integration | Replication integrity, broker boundary, audit persistence | IA, SC, AU, CP |
| 4 | Hardening | Adversarial validation, vulnerability remediation | All (validation) |
| 5 | Operational Readiness | Monitoring, alerting, ATO submission | AU, IR, CP, PM |

## Dependency Graph

```
Phase 1 (Foundation)
    |
    v
Phase 2 (Core Operations)
    |
    v
Phase 3 (Integration)
    |
    v
Phase 4 (Hardening)
    |
    v
Phase 5 (Operational Readiness)
```

Each phase is sequential. Security milestones from earlier phases are prerequisites
for later phases. A failed security milestone blocks progression until resolved.
