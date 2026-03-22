# NIST SP 800-53 Rev. 5 Control Mapping

## Purpose

This document provides a comprehensive mapping of NIST SP 800-53 Rev. 5 security
controls to their implementation in the USG JIT LDAP Server. It is the primary
reference for ATO assessors performing control validation.

Each entry includes: the control identifier, title, a description of how the
system implements (or does not implement) the control, the source module or file
where the implementation resides, code evidence (the NIST comment marker an
assessor can search for), and the implementation status.

## How to Use This Document

1. **Find the control** in the table below.
2. **Note the module/file** path.
3. **Search the codebase** for the control marker: `grep -rn "NIST SP 800-53: <ID>" src/`
4. **Read the code** immediately below the marker comment.
5. **Cross-reference** with [Security Invariants](../../docs/architecture/security-invariants.md)
   for the behavioral guarantee.

## Status Legend

| Status | Meaning |
|---|---|
| **Implemented** | Control behavior is enforced in code with NIST comment markers |
| **Partial** | Some aspects implemented; remaining work identified |
| **Planned** | Design complete; implementation scheduled for a future phase |
| **Operational** | Control is met through operational procedures, not application code |
| **N/A** | Control is not applicable to this system component |

---

## AC — Access Control

### AC-2: Account Management

| Field | Value |
|---|---|
| **Control** | AC-2 |
| **Title** | Account Management |
| **Implementation** | User accounts are managed centrally by the identity management system and replicated to each site via the hub-and-spoke replication protocol. The LDAP server does NOT create, modify, or delete user accounts. It reads replicated account state from the `identity.users` table. Account enablement/disablement is enforced during Bind verification by checking the `enabled` flag. Ephemeral credentials are issued by the external JIT Broker and stored in `runtime.ephemeral_passwords` with TTL enforcement. |
| **Module/File** | `src/db/identity.rs`, `src/replication/puller.rs`, `src/db/runtime.rs` |
| **Code Evidence** | `NIST SP 800-53: AC-2` in identity queries; `identity.user_site_policy` table |
| **Status** | **Implemented** (read-only enforcement); account lifecycle managed externally |

### AC-3: Access Enforcement

| Field | Value |
|---|---|
| **Control** | AC-3 |
| **Title** | Access Enforcement |
| **Implementation** | Access enforcement occurs at two levels. (1) Protocol level: the session state machine (`LdapSession`) enforces that Search operations are only processed for sessions in the `Bound` state. Unauthenticated sessions can only issue Bind or Unbind requests. (2) Database level: PostgreSQL role permissions restrict the LDAP service to SELECT-only on `identity` and SELECT+INSERT on `runtime`. The service cannot modify identity data or escalate privileges. |
| **Module/File** | `src/ldap/session.rs`, `src/ldap/search.rs`, `src/db/pool.rs` |
| **Code Evidence** | `NIST SP 800-53: AC-3` — session state check in search handler |
| **Status** | **Implemented** |

### AC-4: Information Flow Enforcement

| Field | Value |
|---|---|
| **Control** | AC-4 |
| **Title** | Information Flow Enforcement |
| **Implementation** | Information flow is controlled by the dual-schema architecture. The `identity` schema contains replicated directory data (users, groups, memberships). The `runtime` schema contains site-local credential material, bind events, and audit records. These schemas are separated at the PostgreSQL level. The replication puller queries ONLY `identity`. Search operations query ONLY `identity`. Password hashes in `runtime` are never returned in Search results and never included in replication payloads. |
| **Module/File** | `migrations/00001_identity_schema.sql`, `migrations/00002_runtime_schema.sql` |
| **Code Evidence** | Schema separation enforced by migration design and DB role permissions |
| **Status** | **Implemented** |

### AC-6: Least Privilege

| Field | Value |
|---|---|
| **Control** | AC-6 |
| **Title** | Least Privilege |
| **Implementation** | The LDAP service operates with minimum necessary database permissions: SELECT on `identity` schema (read directory data), SELECT on `runtime.ephemeral_passwords` (verify credentials), INSERT on `runtime.bind_events` and `runtime.audit_queue` (logging). It cannot UPDATE or DELETE credentials, cannot write to `identity`, and cannot access other databases. At the LDAP protocol level, only Bind, Search, and Password Modify (for authorized brokers) are implemented. All other LDAP operations return `unwillingToPerform`. |
| **Module/File** | `src/db/pool.rs`, `src/ldap/session.rs`, `src/config.rs` |
| **Code Evidence** | `NIST SP 800-53: AC-6` — minimum permission DB roles; `CM-7` — minimal operations |
| **Status** | **Implemented** |

### AC-7: Unsuccessful Logon Attempts

| Field | Value |
|---|---|
| **Control** | AC-7 |
| **Title** | Unsuccessful Logon Attempts |
| **Implementation** | The `RateLimiter` enforces per-DN bind attempt limits using a sliding window counter stored in `runtime.rate_limit_state`. When a Bind request arrives, the rate limiter is checked BEFORE the password hash is retrieved or computed. If the attempt count exceeds the configured threshold (default: 5 attempts per 60 seconds), the Bind is rejected with `unwillingToPerform` and an audit event is emitted. This prevents both credential guessing and CPU exhaustion via repeated Argon2 computations. |
| **Module/File** | `src/auth/rate_limit.rs` |
| **Code Evidence** | `NIST SP 800-53: AC-7 — Rate limiter checks are performed before password hash retrieval` |
| **Status** | **Implemented** |

### AC-8: System Use Notification

| Field | Value |
|---|---|
| **Control** | AC-8 |
| **Title** | System Use Notification |
| **Implementation** | LDAP protocol does not natively support pre-authentication banners. System use notification is implemented at the client level (SSH banners, PAM messages) rather than at the LDAP server. The LDAP server's `BindResponse` diagnostic message field could carry a notice, but this is not standard LDAP practice and most clients ignore it. |
| **Module/File** | N/A |
| **Code Evidence** | N/A |
| **Status** | **N/A** — implemented at client/PAM layer, not LDAP server |

### AC-12: Session Termination

| Field | Value |
|---|---|
| **Control** | AC-12 |
| **Title** | Session Termination |
| **Implementation** | Sessions are terminated under four conditions: (1) Client sends an Unbind request. (2) TCP connection is closed (graceful or abrupt). (3) Idle timeout expires (configurable, default 300 seconds). (4) Maximum session duration exceeded. When a session terminates, all session state (bound DN, authentication status) is dropped. The `LdapSession` struct is owned by the connection task and destroyed when the task completes. A `ConnectionClosed` audit event records the duration and message count. |
| **Module/File** | `src/ldap/session.rs`, `src/main.rs` (idle timeout in connection handler) |
| **Code Evidence** | `NIST SP 800-53: AC-12` — session termination on Unbind/timeout |
| **Status** | **Implemented** |

### AC-17: Remote Access

| Field | Value |
|---|---|
| **Control** | AC-17 |
| **Title** | Remote Access |
| **Implementation** | All remote access to the LDAP service is via LDAPS (TLS-encrypted LDAP on port 636). There is no plaintext LDAP port, no StartTLS, and no alternative access method. The replication channel between the hub and sites also uses TLS (mutual TLS). Administrative access to the database is out of scope for this application but should use SSH tunnels or mTLS. |
| **Module/File** | `src/tls.rs`, `src/main.rs` |
| **Code Evidence** | `NIST SP 800-53: SC-8` (transport encryption is the AC-17 implementation mechanism) |
| **Status** | **Implemented** |

---

## AU — Audit and Accountability

### AU-2: Audit Events

| Field | Value |
|---|---|
| **Control** | AU-2 |
| **Title** | Audit Events |
| **Implementation** | The `AuditEvent` enum in `src/audit/events.rs` defines the complete set of auditable events: `BindAttempt` (with 7 outcome variants), `SearchRequest`, `SearchComplete`, `PasswordModify`, `RateLimitTriggered`, `TlsError`, `ConfigLoaded`, `ServiceStarted`, `ServiceStopped`, `ConnectionOpened`, `ConnectionClosed`. Every security-relevant action maps to exactly one variant. The enum is exhaustive — adding a new operation without an audit event requires a deliberate code change. |
| **Module/File** | `src/audit/events.rs` |
| **Code Evidence** | `NIST SP 800-53: AU-2` — file header comment |
| **Status** | **Implemented** |

### AU-3: Content of Audit Records

| Field | Value |
|---|---|
| **Control** | AU-3 |
| **Title** | Content of Audit Records |
| **Implementation** | Each audit record includes: event type (what), UTC timestamp (when), source IP address and port (where), subject DN (who), and operation outcome (result). Additional context varies by event type: Search events include base DN, scope, filter summary, and result count. Bind events include outcome classification (Success, InvalidCredentials, AccountLocked, etc.). Password Modify events include broker DN, target DN, and failure reason. Passwords and hashes are NEVER included. |
| **Module/File** | `src/audit/events.rs` |
| **Code Evidence** | `NIST SP 800-53: AU-3` — struct field definitions |
| **Status** | **Implemented** |

### AU-5: Response to Audit Processing Failures

| Field | Value |
|---|---|
| **Control** | AU-5 |
| **Title** | Response to Audit Processing Failures |
| **Implementation** | The audit subsystem uses a fail-open model for audit + fail-closed model for service. If audit event persistence to `runtime.audit_queue` fails (database error), the LDAP operation still completes (preserving availability), but: (1) The event is still emitted via the tracing subscriber (stdout). (2) A metric counter for audit failures is incremented. (3) An alert should be triggered by the monitoring system. The service does NOT continue indefinitely without audit — persistent audit failures should trigger an operational response. |
| **Module/File** | `src/audit/mod.rs` |
| **Code Evidence** | `NIST SP 800-53: AU-5` — audit failure handling |
| **Status** | **Implemented** (fail-open write); **Planned** (automated alerting threshold) |

### AU-6: Audit Review, Analysis, and Reporting

| Field | Value |
|---|---|
| **Control** | AU-6 |
| **Title** | Audit Record Review, Analysis, and Reporting |
| **Implementation** | Audit events are structured as JSON, enabling automated parsing by SIEM systems. The `runtime.audit_queue` table uses JSONB storage for SQL-based ad-hoc queries at the site level. Events are designed for forwarding to a central SIEM for cross-site correlation, alerting rules, and dashboard generation. The [Audit Strategy](audit-strategy.md) document defines recommended SIEM alert rules and manual review schedules. |
| **Module/File** | `src/audit/events.rs`, `runtime.audit_queue` |
| **Code Evidence** | `NIST SP 800-53: AU-6` — structured JSON format |
| **Status** | **Implemented** (format); **Planned** (SIEM integration, alert rules) |

### AU-8: Time Stamps

| Field | Value |
|---|---|
| **Control** | AU-8 |
| **Title** | Time Stamps |
| **Implementation** | All audit event timestamps use `chrono::Utc::now()` for UTC timestamps in ISO 8601 format with millisecond precision. Timestamps are generated at the point of event creation, not at database insertion. The database `created_at` column also records insertion time as a secondary timestamp. NTP synchronization is an operational dependency documented in the operational security guide; the application does not implement or verify time sync. |
| **Module/File** | `src/audit/events.rs` — all event constructors |
| **Code Evidence** | `NIST SP 800-53: AU-8` — file header comment |
| **Status** | **Implemented** (UTC timestamps); **Operational** (NTP synchronization) |

### AU-12: Audit Generation

| Field | Value |
|---|---|
| **Control** | AU-12 |
| **Title** | Audit Record Generation |
| **Implementation** | Audit events are generated at the point of each operation, BEFORE the response is sent to the client. This ensures that even if the connection drops immediately after the response, the event is recorded. The `AuditLogger` provides two output channels: (1) tracing subscriber for immediate structured log output, and (2) database INSERT into `runtime.audit_queue` for durable persistence. Every operation handler in the LDAP processing pipeline calls the audit logger. |
| **Module/File** | `src/audit/mod.rs`, `src/audit/events.rs`, `src/ldap/bind.rs`, `src/ldap/search.rs` |
| **Code Evidence** | `NIST SP 800-53: AU-12 — Audit event is emitted before the Bind response is sent` |
| **Status** | **Implemented** |

---

## IA — Identification and Authentication

### IA-2: Identification and Authentication (Organizational Users)

| Field | Value |
|---|---|
| **Control** | IA-2 |
| **Title** | Identification and Authentication |
| **Implementation** | Users authenticate via LDAPv3 Simple Bind, presenting a Distinguished Name (DN) and password. The DN identifies the user; the password authenticates them. The password is verified against an Argon2id hash stored in `runtime.ephemeral_passwords`. Anonymous Binds (empty DN or empty password) are explicitly rejected — no directory data is accessible without successful authentication. SASL authentication is not supported and is explicitly rejected with `authMethodNotSupported`. |
| **Module/File** | `src/ldap/bind.rs`, `src/auth/password.rs` |
| **Code Evidence** | `NIST SP 800-53: IA-2` — anonymous bind rejection |
| **Status** | **Implemented** |

### IA-4: Identifier Management

| Field | Value |
|---|---|
| **Control** | IA-4 |
| **Title** | Identifier Management |
| **Implementation** | User identifiers (Distinguished Names) are managed centrally by the identity management system and replicated to each site. The LDAP server does not create, modify, or delete identifiers. DNs are stored in `identity.users.dn` with a UNIQUE constraint. The `username` field is also unique. Identifier uniqueness is enforced at the database level. Disabled accounts are tracked via the `enabled` flag. |
| **Module/File** | `src/db/identity.rs`, `migrations/00001_identity_schema.sql` |
| **Code Evidence** | `NIST SP 800-53: IA-4` — central identifier management |
| **Status** | **Implemented** (enforcement); identifier lifecycle managed externally |

### IA-5: Authenticator Management

| Field | Value |
|---|---|
| **Control** | IA-5 |
| **Title** | Authenticator Management |
| **Implementation** | Ephemeral passwords are issued by the external JIT Broker with configurable TTLs (default: 8 hours). Passwords are hashed with Argon2id (memory-hard, GPU/ASIC resistant) before storage in `runtime.ephemeral_passwords`. Plaintext password bytes are zeroized in memory immediately after hashing or verification using the `zeroize` crate. Expired passwords are rejected during Bind verification. Passwords are never logged, never included in error messages, and never replicated. The `used` flag supports single-use credential policy. |
| **Module/File** | `src/auth/password.rs`, `src/ldap/password.rs`, `src/db/runtime.rs` |
| **Code Evidence** | `NIST SP 800-53: IA-5 — Password material is never retained in memory longer than necessary` |
| **Status** | **Implemented** |

### IA-5(1): Password-Based Authentication

| Field | Value |
|---|---|
| **Control** | IA-5(1) |
| **Title** | Password-Based Authentication |
| **Implementation** | Passwords are stored as Argon2id hashes in PHC string format. The Argon2id algorithm is a memory-hard key derivation function that is resistant to GPU and ASIC-based cracking. The hash includes an embedded random salt. Password complexity enforcement is the responsibility of the JIT Broker (not the LDAP server) since the server does not set passwords — it only verifies them. TTL enforcement limits password lifetime. |
| **Module/File** | `src/auth/password.rs` |
| **Code Evidence** | `NIST SP 800-53: IA-5(1)` — file header comment |
| **Status** | **Implemented** |

### IA-8: Identification and Authentication (Non-Organizational Users)

| Field | Value |
|---|---|
| **Control** | IA-8 |
| **Title** | Identification and Authentication (Non-Organizational Users) |
| **Implementation** | The JIT Broker authenticates as a non-organizational service identity using a designated service DN. The `broker_dns` configuration parameter lists the DNs authorized to invoke the Password Modify extended operation. Broker Bind attempts are subject to the same authentication and audit controls as user Bind attempts. Broker identity is recorded in all `PasswordModify` audit events. |
| **Module/File** | `src/config.rs` — `broker_dns`, `src/ldap/password.rs` |
| **Code Evidence** | `NIST SP 800-53: AC-3` — broker authorization check |
| **Status** | **Implemented** |

### IA-11: Re-authentication

| Field | Value |
|---|---|
| **Control** | IA-11 |
| **Title** | Re-authentication |
| **Implementation** | Re-authentication is enforced through session termination. When a connection's idle timeout expires (default: 300 seconds) or the absolute session lifetime is reached (default: 86400 seconds / 24 hours), the session is closed and the client must establish a new TLS connection and Bind again. The absolute lifetime prevents indefinitely held connections regardless of activity. There is no session resumption mechanism. The LDAPv3 protocol also allows re-Bind within a session (the session state machine supports transitioning from `Bound` back to `Bound` with a different DN); re-bind identity changes are logged at WARN level for audit trail. |
| **Module/File** | `src/ldap/session.rs`, `src/main.rs` (idle timeout) |
| **Code Evidence** | `NIST SP 800-53: AC-12` — idle timeout enforcement |
| **Status** | **Implemented** |

---

## SC — System and Communications Protection

### SC-4: Information in Shared Resources

| Field | Value |
|---|---|
| **Control** | SC-4 |
| **Title** | Information in Shared Resources |
| **Implementation** | Session state is per-connection and not shared between connections. Each TLS connection spawns an independent task with its own `LdapSession` struct. No session data is stored in shared data structures accessible to other connections. Password material is zeroized after use, preventing information leakage through memory reuse. The dual-schema design prevents information flow between the identity and runtime security domains. |
| **Module/File** | `src/ldap/session.rs`, `src/auth/password.rs` |
| **Code Evidence** | `NIST SP 800-53: SC-23` — per-connection session isolation |
| **Status** | **Implemented** |

### SC-7: Boundary Protection

| Field | Value |
|---|---|
| **Control** | SC-7 |
| **Title** | Boundary Protection |
| **Implementation** | The LDAP server listens exclusively on port 636 (LDAPS). There is no plaintext LDAP listener on port 389. There is no StartTLS mechanism. The configuration validator rejects non-standard ports unless explicitly overridden (for testing only). The replication channel uses mutual TLS. These boundaries ensure that all data in transit is encrypted and that the server presents a minimal network surface. |
| **Module/File** | `src/tls.rs`, `src/config.rs`, `src/main.rs` |
| **Code Evidence** | `NIST SP 800-53: SC-8` — TLS-only listener |
| **Status** | **Implemented** |

### SC-8: Transmission Confidentiality and Integrity

| Field | Value |
|---|---|
| **Control** | SC-8 |
| **Title** | Transmission Confidentiality and Integrity |
| **Implementation** | All LDAP communication is encrypted via TLS 1.3 with AEAD cipher suites (AES-256-GCM or ChaCha20-Poly1305). The TLS layer provides both confidentiality (encryption) and integrity (AEAD authentication tag). There is no plaintext code path — the `TcpListener` is wrapped in a `TlsAcceptor` before any LDAP processing occurs. Connections that fail TLS negotiation are dropped immediately. The replication channel uses mutual TLS for the same guarantees. |
| **Module/File** | `src/tls.rs` |
| **Code Evidence** | `NIST SP 800-53: SC-8 — All client connections are accepted only via TLS` |
| **Status** | **Implemented** |

### SC-12: Cryptographic Key Establishment and Management

| Field | Value |
|---|---|
| **Control** | SC-12 |
| **Title** | Cryptographic Key Establishment and Management |
| **Implementation** | TLS key exchange uses ECDHE (Ephemeral Elliptic Curve Diffie-Hellman) as provided by the rustls default provider. Server certificates are loaded from PEM files at startup and validated (chain, format). Certificate metadata is logged for operational awareness; private keys are NEVER logged. Replication uses mutual TLS with separate certificate sets for hub and site authentication. Certificate rotation procedures are documented in the operational security guide. |
| **Module/File** | `src/tls.rs`, `src/replication/puller.rs` |
| **Code Evidence** | `NIST SP 800-53: SC-12` — key path logging without key disclosure |
| **Status** | **Implemented** (key exchange); **Operational** (certificate lifecycle management) |

### SC-13: Cryptographic Protection

| Field | Value |
|---|---|
| **Control** | SC-13 |
| **Title** | Cryptographic Protection |
| **Implementation** | The system uses the following cryptographic mechanisms: (1) TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305 for transport encryption (via rustls with the ring provider). (2) Argon2id for password hashing (memory-hard KDF). (3) SHA-256 for replication payload integrity verification. (4) ECDHE for TLS key exchange. All cryptographic operations use vetted, audited libraries (rustls, ring, argon2). No custom cryptographic implementations. |
| **Module/File** | `src/tls.rs`, `src/auth/password.rs` |
| **Code Evidence** | `NIST SP 800-53: SC-13 — Only FIPS-compatible ciphersuites and TLS 1.3 are permitted` |
| **Status** | **Implemented** |

### SC-17: Public Key Infrastructure Certificates

| Field | Value |
|---|---|
| **Control** | SC-17 |
| **Title** | Public Key Infrastructure Certificates |
| **Implementation** | Server TLS certificates are loaded from PEM files configured in `config.toml`. At startup, the certificate chain is validated (non-empty, parseable). Certificate metadata (chain position, size) is logged for operational awareness. Certificate validity checking (not-before, not-after) is performed by the TLS library during handshake. A background task monitors certificate expiry hourly, logging WARN/ERROR as certificates approach expiration. The operational security guide covers certificate rotation procedures, expiry monitoring, and CA chain management. |
| **Module/File** | `src/tls.rs` — `load_certificates()`, `log_certificate_info()`, `spawn_cert_expiry_monitor()` |
| **Code Evidence** | `NIST SP 800-53: SC-17` — certificate validation at startup and continuous runtime monitoring |
| **Status** | **Implemented** (loading/validation); **Operational** (rotation, CA management) |

### SC-23: Session Authenticity

| Field | Value |
|---|---|
| **Control** | SC-23 |
| **Title** | Session Authenticity |
| **Implementation** | Each TLS connection has exactly one LDAP session. Session state (authentication status, bound DN, message counter) is stored in a per-connection `LdapSession` struct created when the TLS connection is accepted and dropped when the connection closes. There are no session tokens, cookies, or identifiers that could be transferred between connections. Session state is server-authoritative — the client cannot forge session state. |
| **Module/File** | `src/ldap/session.rs`, `src/main.rs` |
| **Code Evidence** | `NIST SP 800-53: SC-23 — Session authenticity — one LDAP session per TLS connection` |
| **Status** | **Implemented** |

### SC-28: Protection of Information at Rest

| Field | Value |
|---|---|
| **Control** | SC-28 |
| **Title** | Protection of Information at Rest |
| **Implementation** | Password hashes are stored as Argon2id hashes in `runtime.ephemeral_passwords.password_hash`. Plaintext passwords are never stored. At the application level, password bytes are zeroized in memory after use. At the database level, PostgreSQL should be configured with Transparent Data Encryption (TDE) or full-disk encryption (dm-crypt, BitLocker, etc.) for at-rest protection. The dual-schema design ensures password hashes are in the `runtime` schema, which is never replicated. |
| **Module/File** | `src/auth/password.rs`, `migrations/00002_runtime_schema.sql` |
| **Code Evidence** | `NIST SP 800-53: SC-28` — password hash storage |
| **Status** | **Implemented** (application-level hashing/zeroization); **Operational** (disk encryption) |

---

## SI — System and Information Integrity

### SI-4: System Monitoring

| Field | Value |
|---|---|
| **Control** | SI-4 |
| **Title** | System Monitoring |
| **Implementation** | The system provides monitoring through multiple channels: (1) Audit events (bind failures, rate limit triggers, TLS errors) enable real-time security monitoring via SIEM integration. (2) Rate limiting detects brute-force authentication patterns. (3) Replication health tracking detects sync failures, staleness, and anomalies. (4) Structured JSON logging enables automated log analysis. (5) Connection metrics (active count, duration, message rates) support capacity monitoring. |
| **Module/File** | `src/auth/rate_limit.rs`, `src/audit/events.rs`, `src/replication/health.rs` |
| **Code Evidence** | `NIST SP 800-53: SI-4` — rate limiter warning log |
| **Status** | **Implemented** (event generation); **Planned** (monitoring dashboards, alert rules) |

### SI-7: Software, Firmware, and Information Integrity

| Field | Value |
|---|---|
| **Control** | SI-7 |
| **Title** | Software, Firmware, and Information Integrity |
| **Implementation** | Replication payloads include SHA-256 digests (`payload_hash` column) computed at the central hub and verified by the site puller before applying changes. The `verify_entries()` method recomputes the SHA-256 of each payload and rejects entries where the hash does not match. Monotonic sequence numbers detect gaps (logged at WARN for investigation) and internal batch discontinuities. A `protocol_version` field enables safe schema evolution — sites reject entries with unsupported versions. At the build level, `cargo audit` runs in CI to detect known dependency vulnerabilities. Rust's type system prevents many classes of memory corruption that could compromise integrity. |
| **Module/File** | `src/replication/puller.rs` — `verify_entries()`, `REPLICATION_PROTOCOL_VERSION` |
| **Code Evidence** | SHA-256 verification, sequence gap detection, protocol version check |
| **Status** | **Implemented** |

### SI-10: Information Input Validation

| Field | Value |
|---|---|
| **Control** | SI-10 |
| **Title** | Information Input Validation |
| **Implementation** | Input validation occurs at multiple levels: (1) BER/ASN.1 codec performs strict parsing with maximum PDU size enforcement. Malformed messages are rejected and logged. (2) LDAP message fields are validated (protocol version, non-empty DN, non-empty password for Bind). (3) Search filter complexity is bounded. (4) SQL queries use parameterized statements exclusively — no dynamic SQL construction, no string interpolation of user input into queries. (5) DN format is validated as non-empty before rate limit checks (defense-in-depth). |
| **Module/File** | `src/ldap/codec.rs`, `src/ldap/bind.rs`, `src/auth/rate_limit.rs` |
| **Code Evidence** | `NIST SP 800-53: SI-10` — DN validation in rate limiter |
| **Status** | **Implemented** |

---

## CM — Configuration Management

### CM-2: Baseline Configuration

| Field | Value |
|---|---|
| **Control** | CM-2 |
| **Title** | Baseline Configuration |
| **Implementation** | The server configuration is defined in a TOML file (`config.toml`) with a strongly-typed schema (`ServerConfig` struct). The configuration includes all operational parameters: network settings, TLS certificate paths, database connection, replication settings, security policy (rate limits, TTLs, broker DNs), and audit settings. An example configuration (`config.example.toml`) serves as the documented baseline. |
| **Module/File** | `src/config.rs`, `config.example.toml` |
| **Code Evidence** | `NIST SP 800-53: CM-6` — configuration struct definitions |
| **Status** | **Implemented** |

### CM-6: Configuration Settings

| Field | Value |
|---|---|
| **Control** | CM-6 |
| **Title** | Configuration Settings |
| **Implementation** | All security-relevant configuration settings have secure defaults and are validated at startup. The `validate()` function enforces: (1) Port must be 636 unless explicitly overridden for testing. (2) TLS certificate and key files must exist. (3) TLS minimum version must be "1.3". (4) Database URL must not be empty. (5) Rate limit parameters must be positive. (6) Replication settings are validated when enabled. The server refuses to start if any validation fails. Configuration is immutable after startup — there is no runtime reconfiguration of security settings. |
| **Module/File** | `src/config.rs` — `validate()` |
| **Code Evidence** | `NIST SP 800-53: CM-6 — Configuration settings loaded from validated file` |
| **Status** | **Implemented** |

### CM-7: Least Functionality

| Field | Value |
|---|---|
| **Control** | CM-7 |
| **Title** | Least Functionality |
| **Implementation** | The LDAP server implements only three operations: Bind (authentication), Search (directory lookup), and Password Modify extended operation (credential issuance). All other LDAPv3 operations (Add, Delete, Modify, ModifyDN, Compare, Abandon) are explicitly not implemented. Unrecognized operations return `unwillingToPerform`. The StartTLS OID is not recognized. SASL authentication is rejected. This minimal operation set reduces the attack surface and simplifies security analysis. |
| **Module/File** | `src/ldap/session.rs`, `src/ldap/mod.rs` |
| **Code Evidence** | `NIST SP 800-53: CM-7` — minimal operation set |
| **Status** | **Implemented** |

---

## Summary Table

| Control | Title | Status | Primary Module |
|---|---|---|---|
| AC-2 | Account Management | Implemented (read) | `src/db/identity.rs` |
| AC-3 | Access Enforcement | Implemented | `src/ldap/session.rs` |
| AC-4 | Information Flow Enforcement | Implemented | Schema design |
| AC-6 | Least Privilege | Implemented | `src/db/pool.rs` |
| AC-7 | Unsuccessful Logon Attempts | Implemented | `src/auth/rate_limit.rs` |
| AC-8 | System Use Notification | N/A | Client layer |
| AC-12 | Session Termination | Implemented | `src/ldap/session.rs` |
| AC-17 | Remote Access | Implemented | `src/tls.rs` |
| AU-2 | Audit Events | Implemented | `src/audit/events.rs` |
| AU-3 | Content of Audit Records | Implemented | `src/audit/events.rs` |
| AU-5 | Response to Audit Failures | Implemented | `src/audit/mod.rs` |
| AU-6 | Audit Review/Analysis | Partial | `src/audit/events.rs` |
| AU-8 | Time Stamps | Implemented | `src/audit/events.rs` |
| AU-12 | Audit Generation | Implemented | `src/audit/events.rs` |
| IA-2 | Identification and Auth | Implemented | `src/ldap/bind.rs` |
| IA-4 | Identifier Management | Implemented | `src/db/identity.rs` |
| IA-5 | Authenticator Management | Implemented | `src/auth/password.rs` |
| IA-5(1) | Password-Based Auth | Implemented | `src/auth/password.rs` |
| IA-8 | Non-Org User Auth | Implemented | `src/config.rs` |
| IA-11 | Re-authentication | Implemented | `src/ldap/session.rs` |
| SC-4 | Shared Resources | Implemented | `src/ldap/session.rs` |
| SC-7 | Boundary Protection | Implemented | `src/tls.rs` |
| SC-8 | Transmission Confidentiality | Implemented | `src/tls.rs` |
| SC-12 | Key Establishment | Implemented | `src/tls.rs` |
| SC-13 | Cryptographic Protection | Implemented | `src/tls.rs`, `src/auth/password.rs` |
| SC-17 | PKI Certificates | Implemented | `src/tls.rs` |
| SC-23 | Session Authenticity | Implemented | `src/ldap/session.rs` |
| SC-28 | Information at Rest | Implemented | `src/auth/password.rs` |
| SI-4 | System Monitoring | Partial | `src/audit/events.rs` |
| SI-7 | Information Integrity | Implemented | `src/replication/puller.rs` |
| SI-10 | Input Validation | Implemented | `src/ldap/codec.rs` |
| CM-2 | Baseline Configuration | Implemented | `src/config.rs` |
| CM-6 | Configuration Settings | Implemented | `src/config.rs` |
| CM-7 | Least Functionality | Implemented | `src/ldap/session.rs` |
