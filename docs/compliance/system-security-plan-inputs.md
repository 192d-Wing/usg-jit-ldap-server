# System Security Plan Inputs

This document provides assessor-ready control implementation statements for the
USG JIT LDAP Server, organized by NIST SP 800-53 Rev. 5 control family. Each
statement is written for direct inclusion in a System Security Plan (SSP).

For the detailed control-to-code mapping with file and line references, see the
[NIST Traceability Matrix](nist-traceability-matrix.md). For the full control
analysis, see
[../security/nist-sp800-53-rev5-mapping.md](../security/nist-sp800-53-rev5-mapping.md).

---

## System Description

### System Name

USG JIT LDAP Server

### System Purpose

The USG JIT LDAP Server is a purpose-built, minimal LDAPv3 directory service
designed for a Just-In-Time (JIT) password broker environment spanning 184
geographically distributed sites. It provides LDAPS-only identity lookups and
Simple Bind authentication against a PostgreSQL backend. An external JIT Broker
issues ephemeral passwords that are stored site-locally and never replicated.

### Authorization Boundary

The authorization boundary encompasses:

- The LDAP server process (Rust binary)
- The site-local PostgreSQL database (identity and runtime schemas)
- The TLS listener on port 636
- The replication channel to the central hub (mTLS)
- Configuration files and TLS certificate material on the host filesystem

Out of scope: the JIT Broker application, the central hub control plane, host
operating system, PKI certificate authority, and client applications (PAM, SSH).

### Data Flows

1. **Client to LDAP Server (LDAPS):** TLS 1.3 on port 636. Clients send
   Bind requests (DN + password) and Search requests. Server returns Bind
   responses and Search result entries. All traffic is encrypted.

2. **LDAP Server to PostgreSQL:** Local TCP or Unix socket connection. Server
   reads identity data (users, groups) from the `identity` schema and reads/
   writes credential and audit data in the `runtime` schema.

3. **Central Hub to Site (Replication):** Mutual TLS connection. Identity-only
   data flows one-way from hub to site. Credential material in the `runtime`
   schema is never replicated.

4. **JIT Broker to LDAP Server (Password Modify):** Broker authenticates via
   LDAPS Bind, then issues Password Modify extended operations to set ephemeral
   passwords for target users.

---

## AC — Access Control

### AC-2: Account Management

User accounts are managed centrally by the identity management system and
replicated to each site via the hub-and-spoke replication protocol. The LDAP
server does not create, modify, or delete user accounts; it reads replicated
account state from the `identity.users` table and enforces the `enabled` flag
during Bind verification.

### AC-3: Access Enforcement

Access enforcement occurs at multiple layers. At the protocol level, the session
state machine enforces that Search and Password Modify operations are only
processed for sessions in the `Bound` state; unauthenticated sessions can only
issue Bind or Unbind requests. At the database level, PostgreSQL role permissions
restrict the LDAP service to SELECT-only on `identity` and SELECT+INSERT on
`runtime`. The Password Modify operation additionally verifies that the bound
identity is an authorized broker DN before permitting credential issuance.

### AC-4: Information Flow Enforcement

Information flow is controlled by the dual-schema architecture. The `identity`
schema contains replicated directory data (users, groups, memberships). The
`runtime` schema contains site-local credential material, bind events, and audit
records. These schemas are separated at the PostgreSQL level with distinct role
permissions. Password hashes in `runtime` are never returned in Search results
and never included in replication payloads.

### AC-6: Least Privilege

The LDAP service operates with minimum necessary database permissions: SELECT on
`identity` (read directory data), SELECT on `runtime.ephemeral_passwords` (verify
credentials), INSERT on `runtime.bind_events` and `runtime.audit_queue`
(logging). At the protocol level, only Bind, Search, and Password Modify are
implemented; all other LDAPv3 operations return `unwillingToPerform`.

### AC-7: Unsuccessful Logon Attempts

The rate limiter enforces both per-DN and per-source-IP bind attempt limits
using sliding window counters. When a Bind request arrives, both rate limiters
are checked before the password hash is retrieved or computed. If either
attempt count exceeds its configured threshold (per-DN default: 5 attempts
per 60 seconds; per-IP default: 50 attempts per 300 seconds), the Bind is
rejected with `unwillingToPerform` and an audit event is emitted. The per-DN
limiter prevents credential guessing against individual accounts, while the
per-IP limiter prevents distributed brute-force attacks that rotate through
many DNs from a single source. Both checks occur before Argon2 computation
to prevent CPU exhaustion.

---

## AU — Audit and Accountability

### AU-2: Audit Events

The audit subsystem defines a comprehensive set of auditable events covering
every security-relevant operation: Bind attempts (with 7 outcome variants),
Search requests and completions, Password Modify operations, rate limit
triggers, TLS errors, configuration loads, service start/stop, and connection
open/close. The event enum is exhaustive -- adding a new operation without an
audit event requires a deliberate code change.

### AU-3: Content of Audit Records

Each audit record includes: event type (what), UTC timestamp (when), source IP
address and port (where), subject DN (who), and operation outcome (result).
Additional context varies by event type: Search events include base DN, scope,
filter summary, and result count; Bind events include outcome classification;
Password Modify events include broker DN and target DN. Passwords and hashes are
never included in audit records.

### AU-5: Response to Audit Processing Failures

The audit subsystem supports configurable fail-open and fail-closed modes. In
fail-closed mode, if audit event persistence to `runtime.audit_queue` fails, the
LDAP operation (Bind) is rejected. In fail-open mode, the event is still emitted
via the tracing subscriber (stdout) and a failure counter is incremented.
Persistent audit failures are expected to trigger an operational alert.

### AU-6: Audit Review, Analysis, and Reporting

Audit events are structured as JSON, enabling automated parsing by SIEM systems.
The `runtime.audit_queue` table uses JSONB storage for SQL-based ad-hoc queries
at the site level. Events are designed for forwarding to a central SIEM for
cross-site correlation, alerting rules, and dashboard generation.

### AU-8: Time Stamps

All audit event timestamps use UTC in ISO 8601 format with millisecond
precision. Timestamps are generated at the point of event creation, not at
database insertion. NTP synchronization is an operational dependency; the
application does not implement or verify time sync.

### AU-12: Audit Record Generation

Audit events are generated at the point of each operation, before the response
is sent to the client. This ensures that even if the connection drops
immediately after the response, the event is recorded. The audit logger provides
two output channels: tracing subscriber for immediate structured log output, and
database INSERT into `runtime.audit_queue` for durable persistence.

---

## CM — Configuration Management

### CM-2: Baseline Configuration

The server configuration is defined in a strongly-typed TOML file with a schema
enforced by the `ServerConfig` Rust struct. An example configuration
(`config.example.toml`) serves as the documented baseline. All security-relevant
parameters have secure defaults.

### CM-6: Configuration Settings

All security-relevant configuration settings are validated at startup. The
`validate()` function enforces: port must be 636 unless explicitly overridden,
TLS certificate and key files must exist, TLS minimum version must be 1.3,
database URL must not be empty, and rate limit parameters must be positive.
The server refuses to start if any validation fails. Configuration is immutable
after startup -- there is no runtime reconfiguration of security settings.

### CM-7: Least Functionality

The LDAP server implements only three operations: Bind (authentication), Search
(directory lookup), and Password Modify extended operation (credential issuance).
All other LDAPv3 operations are explicitly not implemented and return
`unwillingToPerform`. StartTLS is not recognized. SASL authentication is
rejected. This minimal operation set reduces the attack surface.

---

## CP — Contingency Planning

### CP-9: System Backup

The hub-and-spoke replication architecture provides local survivability. Each
site maintains a complete copy of the identity directory in its local PostgreSQL
instance. If the central hub becomes unavailable, sites continue to authenticate
users against locally replicated data. Replication health monitoring detects sync
failures and staleness.

### CP-10: System Recovery

Recovery from replication gaps uses monotonic sequence numbers to detect missing
data and re-synchronize from the central hub. Exponential backoff prevents
reconnection storms. The replication recovery runbook documents manual
intervention procedures for extended outages.

---

## IA — Identification and Authentication

### IA-2: Identification and Authentication (Organizational Users)

Users authenticate via LDAPv3 Simple Bind, presenting a Distinguished Name (DN)
and password. The DN identifies the user; the password authenticates them against
an Argon2id hash stored in `runtime.ephemeral_passwords`. Anonymous Binds (empty
DN or empty password) are explicitly rejected. SASL authentication is not
supported. On unknown DNs, a dummy hash verification is performed to prevent
timing-based user enumeration.

### IA-5: Authenticator Management

Ephemeral passwords are issued by the external JIT Broker with configurable TTLs
(default: 8 hours). Passwords are hashed with Argon2id using hardened parameters
(m=65536/64 MiB, t=3 iterations, p=4 parallelism) which exceed NIST SP 800-63B
minimums and provide strong resistance to GPU/ASIC attacks. Plaintext password
bytes are zeroized in memory immediately after hashing or verification using the
`zeroize` crate, including on error paths. Expired
passwords are rejected during Bind verification. Passwords are never logged,
never included in error messages, and never replicated. The `used` flag supports
single-use credential policy with transactional locking.

### IA-5(1): Password-Based Authentication

Passwords are stored as Argon2id hashes in PHC string format with embedded
random salts and hardened parameters (m=65536, t=3, p=4). The Argon2id
algorithm is memory-hard and resistant to GPU and ASIC-based cracking. Password complexity enforcement is the responsibility of
the JIT Broker since the LDAP server only verifies passwords, not sets them.
TTL enforcement limits password lifetime.

---

## SC — System and Communications Protection

### SC-4: Information in Shared Resources

Session state is per-connection and not shared between connections. Each TLS
connection spawns an independent task with its own session struct. Password
material is zeroized after use, preventing information leakage through memory
reuse. The dual-schema design prevents information flow between the identity and
runtime security domains.

### SC-5: Denial of Service Protection

The server enforces a configurable maximum concurrent connection limit. TLS
handshake timeouts prevent slow-handshake attacks. Connection idle timeouts
reclaim resources from inactive sessions. Rate limiting on Bind attempts reduces
hash computation load. Query result size limits and query timeouts prevent
resource exhaustion from complex searches.

### SC-8: Transmission Confidentiality and Integrity

All LDAP communication is encrypted via TLS 1.3+ with AEAD cipher suites
(AES-256-GCM or ChaCha20-Poly1305). There is no plaintext code path -- the TCP
listener is wrapped in a TLS acceptor before any LDAP processing occurs.
Connections that fail TLS negotiation are dropped immediately. The replication
channel uses mutual TLS for the same guarantees. The server refuses to start
without valid TLS certificates.

### SC-12: Cryptographic Key Establishment and Management

TLS key exchange uses ECDHE (Ephemeral Elliptic Curve Diffie-Hellman). Server
certificates are loaded from PEM files at startup and validated. Certificate
metadata is logged for operational awareness; private keys are never logged.
Certificate rotation procedures are documented in the operational security guide.

### SC-13: Cryptographic Protection

The system uses: TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305 for
transport (via rustls with the ring provider), Argon2id for password hashing,
SHA-256 for replication payload integrity, and ECDHE for key exchange. All
cryptographic operations use vetted, audited libraries. No custom cryptographic
implementations exist in the codebase.

### SC-17: PKI Certificates

Server TLS certificates are loaded from PEM files and validated at startup
(non-empty, parseable, valid chain). Certificate validity checking is performed
by the TLS library during handshake. A background task monitors certificate
expiry hourly, logging warnings as certificates approach expiration. The
operational security guide covers certificate rotation, expiry monitoring,
and CA chain management.

### SC-23: Session Authenticity

Each TLS connection has exactly one LDAP session. Session state is stored in a
per-connection struct created at TLS acceptance and dropped at connection close.
There are no session tokens, cookies, or identifiers that could be transferred
between connections. Session state is server-authoritative.

### SC-28: Protection of Information at Rest

Password hashes are stored as Argon2id hashes; plaintext passwords are never
stored. At the application level, password bytes are zeroized in memory after
use. At the database level, PostgreSQL should be configured with full-disk
encryption for at-rest protection (operational responsibility).

---

## SI — System and Information Integrity

### SI-4: System Monitoring

The system provides monitoring through multiple channels: audit events for
real-time security monitoring via SIEM integration, rate limiting for brute-force
detection, replication health tracking for sync failure detection, structured
JSON logging for automated analysis, and connection metrics for capacity
monitoring. An admin health endpoint provides runtime operational awareness.

### SI-7: Software, Firmware, and Information Integrity

Replication payloads include SHA-256 digests for integrity verification.
Monotonic sequence numbers detect gaps and replay attempts. The replication
puller verifies payload integrity before applying changes. At the build level,
`cargo audit` and `cargo deny` are configured for dependency vulnerability
scanning.

### SI-10: Information Input Validation

Input validation occurs at multiple levels: the BER/ASN.1 codec performs strict
parsing with maximum PDU size enforcement (malformed messages are rejected and
logged); LDAP message fields are validated (protocol version, non-empty DN,
non-empty password); search filter complexity is bounded by a depth limit; SQL
queries use parameterized statements exclusively with LIKE wildcard escaping;
and DN format is validated before rate limit checks as defense-in-depth.
