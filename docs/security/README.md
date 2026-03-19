# Security Overview: USG JIT LDAP Server

## Security Posture Summary

The USG JIT LDAP Server is a narrow-scope, security-focused LDAPS service designed
for US Government JIT (Just-In-Time) password broker environments. It provides
LDAP authentication and directory lookup at 184 geographically distributed sites,
backed by PostgreSQL with a dual-schema architecture that enforces strict separation
between replicated identity data and site-local credential material.

The system is built in Rust to leverage compile-time memory safety guarantees, uses
a minimal dependency footprint for auditability, and embeds NIST SP 800-53 Rev. 5
control references directly in the source code for ATO traceability.

**Classification:** The system handles PII (user directory data) and authentication
credentials (ephemeral password hashes). It is designed to operate at a security
level consistent with FISMA Moderate or High baselines.

## Key Security Properties

### 1. Fail-Closed Design

The server refuses to start if TLS certificate material is unavailable, corrupted,
or expired. There is no degraded mode that falls back to plaintext. If the TLS
acceptor cannot be constructed, the process exits with a non-zero status code.

At runtime, if the TLS acceptor becomes unusable (e.g., after a failed certificate
hot-reload), the listener stops accepting new connections rather than downgrading.

**Enforcement:** `src/tls.rs` — `build_tls_acceptor()` returns `Err` on any
certificate loading failure; `src/main.rs` exits on `Err`.

### 2. TLS-Only Transport

There is no code path that accepts plaintext LDAP connections. The server listens
exclusively on port 636 (LDAPS). Port 389 is never opened. StartTLS is not
implemented — the `ExtendedRequest` handler does not recognize the StartTLS OID.

Only TLS 1.2 and 1.3 are accepted. Cipher suites are restricted to AEAD algorithms
(AES-256-GCM, ChaCha20-Poly1305) via the rustls default provider.

**Enforcement:** `src/tls.rs` — `build_server_config()` constructs a rustls
`ServerConfig` with `builder_with_protocol_versions(&[TLS12, TLS13])`.

### 3. Password Material Zeroization

All plaintext password bytes are zeroized in memory immediately after hashing or
verification. The `zeroize` crate's `Zeroize` trait is applied to password buffers,
ensuring the underlying memory is overwritten with zeros when the buffer is dropped
or explicitly zeroized.

Password material is never logged, never included in error messages, and never
stored in any data structure that outlives the Bind operation.

**Enforcement:** `src/auth/password.rs` — `hash_password()` and `verify_password()`
call `plaintext.zeroize()` after use.

### 4. Rate Limiting on Authentication

Bind attempts are rate-limited per DN using a database-backed sliding window
counter. The rate limiter is checked BEFORE password hash retrieval or computation,
preventing CPU exhaustion attacks via repeated Argon2 invocations.

Default thresholds: 5 attempts per DN per 60-second window (configurable).

**Enforcement:** `src/auth/rate_limit.rs` — `RateLimiter::check_and_increment()`
uses an atomic upsert against `runtime.rate_limit_state`.

### 5. Comprehensive Audit Logging

Every security-relevant operation produces a structured audit event:
- Bind attempts (success and failure, with outcome classification)
- Search requests and completions
- Password Modify operations (broker issuance)
- Rate limit triggers
- TLS errors
- Connection open/close with duration and message counts
- Service lifecycle (start, stop, config load)

Events are serialized as JSON and persisted to `runtime.audit_queue` for
durable storage and forwarding to a central SIEM.

**Enforcement:** `src/audit/events.rs` — `AuditEvent` enum with 11 variants
covering all operation types.

### 6. Schema-Level Data Isolation

PostgreSQL schemas enforce a hard boundary between replicated identity data
(`identity` schema) and site-local credential material (`runtime` schema).
The replication puller has no `SELECT` privilege on `runtime` tables. Password
hashes cannot be exfiltrated via the replication channel.

**Enforcement:** SQL migrations `00001_identity_schema.sql` and
`00002_runtime_schema.sql`; PostgreSQL role permissions.

## Threat Landscape

This system faces threats typical of a distributed authentication service in a
government environment:

| Threat Category | Relevance | Primary Mitigations |
|---|---|---|
| Credential stuffing / brute force | High | Rate limiting, ephemeral passwords, audit + alerting |
| Credential replay | Medium | TLS encryption, short-lived ephemeral passwords |
| Man-in-the-middle | Medium | LDAPS-only (no StartTLS stripping), mutual TLS on replication |
| Data exfiltration | Medium | Bind-before-search, result size limits, schema separation |
| Insider threat | Medium | Audit logging, schema separation, DB role separation |
| Denial of service | Medium | Connection limits, rate limiting, query timeouts |
| Replication poisoning | Low-Medium | Mutual TLS, payload integrity verification, sequence numbers |
| Rogue JIT Broker | Low | Broker authorization boundary, TTL enforcement, audit logging |
| TLS downgrade | Low | No plaintext code path, no StartTLS, fail-closed |
| Supply chain attack | Low | Minimal dependencies, Rust memory safety, `cargo audit` |

## Defense-in-Depth Layers

The system implements defense at multiple layers, so that failure of any single
control does not compromise the overall security posture.

### Layer 1: Network Transport (TLS)
- LDAPS-only, TLS 1.2+ with AEAD ciphers
- No plaintext code path, no StartTLS
- Fail-closed on certificate unavailability
- Mutual TLS on replication channel

### Layer 2: Protocol Enforcement
- Session state machine: `Connected -> Bound -> Closed`
- Bind required before Search (no anonymous access)
- Strict BER/ASN.1 parsing with maximum PDU size
- Only Bind, Search, and Password Modify supported; all other operations rejected

### Layer 3: Authentication Controls
- Argon2id password hashing (memory-hard, GPU/ASIC resistant)
- Per-DN rate limiting checked before hash computation
- Ephemeral passwords with TTL enforcement
- Password zeroization after use
- Constant-time hash comparison (Argon2 library guarantee)

### Layer 4: Authorization and Access Control
- Session state-based access control (must be Bound to Search)
- Database role permissions enforce least privilege per schema
- Broker authorization boundary (only designated DNs can issue passwords)
- Search result size limits enforced server-side

### Layer 5: Data Protection
- Schema-level separation: identity (replicated) vs. runtime (local-only)
- Password hashes never leave the site boundary
- No password hashes in Search results (different schema, no code path)
- Parameterized SQL queries (no injection)

### Layer 6: Audit and Monitoring
- All security-relevant operations produce structured audit events
- Events persisted to `runtime.audit_queue` for durability
- Events forwarded to central SIEM for correlation and alerting
- Replication health monitoring detects anomalies

### Layer 7: Operational Controls
- Configuration validated at startup; insecure settings rejected
- Secure defaults for all security parameters
- Immutable runtime configuration (no hot-reconfiguration of security settings)
- Structured JSON logging for automated analysis

## Security Assumptions and Trust Model

### Trusted Components

| Component | Trust Basis |
|---|---|
| Rust runtime | Memory safety via ownership model; no `unsafe` blocks |
| rustls TLS library | Pure-Rust, audited, FIPS-compatible provider |
| PostgreSQL | Correctly configured and patched; role-based access enforced |
| JIT Broker | Honest issuer; does not issue credentials to unauthorized parties |
| Host operating system | Hardened per site baseline; process isolation enforced |
| PKI infrastructure | Certificates are valid; CA is not compromised |
| NTP / time synchronization | Clocks are approximately synchronized across sites |

### Explicitly Untrusted

| Component | Treatment |
|---|---|
| LDAP clients | Authenticated via Bind before any data access |
| Network between client and server | Encrypted via TLS; assumed hostile |
| Network between sites | Encrypted via mutual TLS; assumed hostile |
| User-supplied LDAP messages | Validated by strict BER parser; bounded size |
| Search filters | Complexity-limited; parameterized SQL execution |

### What This System Does NOT Protect Against

1. A compromised JIT Broker (can issue arbitrary credentials; mitigated only by
   TTL enforcement and audit logging for post-incident forensics)
2. A compromised host operating system (negates all application-level memory
   protection, including zeroization)
3. A compromised PostgreSQL instance (undermines schema-level access controls)
4. Physical access to site hardware (addressed by physical security controls)
5. Supply chain attacks on the Rust toolchain or cargo registry (addressed by
   build pipeline controls and dependency auditing)

## Related Documents

- [Abuse Cases](abuse-cases.md) — detailed attack scenarios and mitigations
- [Audit Strategy](audit-strategy.md) — audit logging design and SIEM integration
- [NIST SP 800-53 Rev. 5 Mapping](nist-sp800-53-rev5-mapping.md) — control-by-control implementation evidence
- [Code Review Checklist](code-review-checklist.md) — security review criteria
- [Operational Security](operational-security.md) — operational procedures and guidance
- [Implementation Phases](implementation-phases.md) — phased security milestones
- [Threat Model](../../docs/architecture/threat-model.md) — STRIDE analysis
- [Security Invariants](../../docs/architecture/security-invariants.md) — non-negotiable properties
- [Trust Boundaries](../../docs/architecture/trust-boundaries.md) — boundary definitions
