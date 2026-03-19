# Threat Model

This document presents a structured threat analysis for the USG JIT LDAP
Server. It uses the STRIDE methodology applied to each major component and
trust boundary, identifies specific attack vectors, and maps mitigations to
design decisions.

## Scope

**In scope:**
- The LDAP server process and its interfaces
- PostgreSQL as accessed by the LDAP server
- Replication channel between central hub and sites
- JIT Broker integration points
- Network communication paths

**Out of scope:**
- Host operating system security (covered by site hardening baselines)
- Physical security of site infrastructure
- PKI certificate authority operations
- JIT Broker internal implementation
- PostgreSQL engine vulnerabilities
- Client-side security (PAM modules, SSH configurations)

## STRIDE Analysis by Component

### LDAPS Listener (`src/tls.rs`, `src/main.rs`)

| Threat | Category | Description | Mitigation |
|---|---|---|---|
| T-L1 | **Spoofing** | Attacker impersonates the LDAP server with a rogue certificate | Server certificate is pinned or CA-validated by clients. Certificate rotation uses the project PKI. |
| T-L2 | **Tampering** | Attacker modifies data in transit | TLS with AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305) provides integrity. |
| T-L3 | **Repudiation** | Client denies having connected | TLS session is logged with client IP, connection time, and TLS parameters in audit log. |
| T-L4 | **Information Disclosure** | TLS downgrade exposes credentials | Only TLS 1.2+ is accepted. No StartTLS. No plaintext port. Cipher suite is restricted. |
| T-L5 | **Denial of Service** | TLS handshake flood exhausts resources | Connection rate limiting at listener. Maximum concurrent connection cap. TLS handshake timeout. |
| T-L6 | **Elevation of Privilege** | Exploit in TLS library grants code execution | Rust memory safety. Minimal dependency set. TLS library (rustls) is a pure-Rust, audited implementation. |

### Session Handler (`src/ldap/session.rs`)

| Threat | Category | Description | Mitigation |
|---|---|---|---|
| T-S1 | **Spoofing** | Attacker uses stolen credentials to Bind as another user | Ephemeral passwords with TTLs limit the window. Rate limiting detects stuffing. Audit log enables detection. |
| T-S2 | **Tampering** | Malformed LDAP PDU exploits parsing | Strict BER/ASN.1 parser with maximum PDU size. Rust memory safety prevents buffer overflows. |
| T-S3 | **Repudiation** | Authenticated user denies performing a Search | All operations are logged with bound DN, timestamp, and client IP. |
| T-S4 | **Information Disclosure** | Unauth'd client reads directory data | Session state machine enforces Bind-before-Search. No anonymous reads. |
| T-S5 | **Denial of Service** | Client opens many sessions, sends large queries | Per-connection memory limits. Maximum concurrent sessions. Query result size limits. |
| T-S6 | **Elevation of Privilege** | Session state confusion allows bypass | State machine is a Rust enum with exhaustive match. No invalid state transitions are representable. |

### Bind Handler (`src/ldap/bind.rs`, `src/auth/password.rs`)

| Threat | Category | Description | Mitigation |
|---|---|---|---|
| T-B1 | **Spoofing** | Credential stuffing / brute force | Per-DN and per-IP rate limiting. Account lockout after threshold. Ephemeral passwords expire. |
| T-B2 | **Tampering** | Replay of captured Bind PDU | TLS prevents capture. Even if captured, ephemeral passwords expire quickly. |
| T-B3 | **Information Disclosure** | Timing side-channel reveals password validity | Constant-time hash comparison. Same error response for "user not found" and "wrong password." |
| T-B4 | **Information Disclosure** | Password hash leaked from memory | Password material is zeroized after verification using `zeroize` crate. |
| T-B5 | **Denial of Service** | Flood of Bind requests overwhelms hash computation | Rate limiter rejects excess attempts before hash computation. Argon2 cost tuned to site hardware. |

### Search Handler (`src/ldap/search.rs`)

| Threat | Category | Description | Mitigation |
|---|---|---|---|
| T-Q1 | **Information Disclosure** | Overly broad Search returns sensitive attributes | Search scope restricted to `identity` schema. Password hashes are in `runtime` and never returned. Attribute filtering enforced server-side. |
| T-Q2 | **Denial of Service** | Complex filter causes expensive query | Filter complexity limit. Query timeout. Maximum result entry count (sizelimit). |
| T-Q3 | **Information Disclosure** | Search enumerates all directory entries | Base/scope restrictions per bound DN if configured. Size limit enforced. All searches audited. |

### PostgreSQL Backend (`src/db/`)

| Threat | Category | Description | Mitigation |
|---|---|---|---|
| T-D1 | **Tampering** | SQL injection modifies data | All queries use parameterized statements. No dynamic SQL construction. |
| T-D2 | **Information Disclosure** | LDAP service reads password hashes beyond its scope | PostgreSQL row-level security restricts credential reads to local site scope. |
| T-D3 | **Elevation of Privilege** | LDAP service role writes to identity schema | Role has `SELECT`-only on `identity`. Enforced at PostgreSQL role level. |
| T-D4 | **Tampering** | Attacker modifies identity data via database | LDAP service role cannot write to `identity`. Only the replication puller role can. |

### Replication Puller (`src/replication/`)

| Threat | Category | Description | Mitigation |
|---|---|---|---|
| T-R1 | **Spoofing** | Attacker impersonates central hub | Mutual TLS with certificate pinning. Site validates hub's certificate. |
| T-R2 | **Tampering** | Replication payload is modified in transit | mTLS integrity. Payload includes SHA-256 digest. Sequence numbers detect gaps. |
| T-R3 | **Information Disclosure** | Replication channel leaks password data | Schema-level enforcement: replication queries only read `identity` schema. Passwords are in `runtime`, which is excluded. |
| T-R4 | **Denial of Service** | Fake hub sends massive payloads | Maximum payload size. Rate limiting on replication pulls. Anomaly detection on change set size. |
| T-R5 | **Spoofing** | Rogue site impersonates another site | Site certificate CN must match registered site ID. Hub validates before serving data. |

### JIT Broker Integration (`src/ldap/password.rs`, `src/db/runtime.rs`)

| Threat | Category | Description | Mitigation |
|---|---|---|---|
| T-J1 | **Spoofing** | Attacker impersonates JIT Broker | Broker authenticates with dedicated service credential (certificate or token). Dedicated DN with `password-issuer` role. |
| T-J2 | **Tampering** | Attacker issues long-lived passwords | Server-side TTL enforcement. Maximum TTL cap in configuration. |
| T-J3 | **Repudiation** | Broker denies issuing a password | All issuance events are audit-logged with Broker identity, target DN, TTL, and timestamp. |
| T-J4 | **Elevation of Privilege** | Broker role escalates to identity writes | Broker's database role is scoped to `runtime.credentials` INSERT/UPDATE only. No access to `identity` schema. |

## Attack Vector Analysis

### 1. Credential Stuffing

**Vector:** Attacker uses lists of compromised credentials from other breaches
to attempt Bind operations.

**Mitigations:**
- Per-DN rate limiting: max N attempts per DN per time window
- Per-IP rate limiting: max M attempts per source IP per time window
- Account lockout after configurable threshold (temporary, not permanent)
- Ephemeral passwords from JIT Broker are unique per issuance, not reused
- Audit log enables real-time detection via SIEM integration
- Failed Bind responses use constant timing to prevent enumeration

### 2. Replay Attack

**Vector:** Attacker captures a valid Bind PDU and replays it.

**Mitigations:**
- TLS encryption prevents capture of Bind PDU content on the wire
- Even if TLS is somehow compromised, ephemeral passwords have short TTLs
- TLS session is unique per connection; replayed raw bytes would not form a
  valid TLS session
- Audit log would show duplicate Bind patterns

### 3. Man-in-the-Middle (MitM)

**Vector:** Attacker intercepts communication between client and server.

**Mitigations:**
- LDAPS-only design: TLS is established before any LDAP data is exchanged
- No StartTLS means no opportunity for TLS stripping
- Server certificate validates identity; clients verify the certificate chain
- Replication channel uses mutual TLS, preventing MitM on replication

### 4. Data Exfiltration

**Vector:** Attacker extracts directory data (user listings, group memberships)
or credential material.

**Mitigations:**
- Search requires successful Bind first (no anonymous access)
- Search result size limits prevent bulk extraction
- Password hashes are stored in the `runtime` schema and never returned in
  Search results
- Password material is zeroized in application memory after use
- Audit logging detects unusual Search patterns (high volume, broad scope)
- Database role permissions restrict access to minimum necessary tables

### 5. Insider Threat

**Vector:** Authorized administrator or operator misuses access.

**Mitigations:**
- All operations are audit-logged, including administrative actions
- Audit log is append-only from the LDAP service perspective
- Password material in `runtime` is hashed; raw passwords are never stored
- Database roles enforce separation of duties (LDAP service role vs. Broker
  role vs. admin role)
- Replication metadata is tracked; unauthorized changes to identity data
  would be detected at reconciliation
- Code comments map to NIST controls, enabling auditor review

### 6. Denial of Service (Resource Exhaustion)

**Vector:** Attacker exhausts server resources (connections, memory, CPU,
database connections).

**Mitigations:**
- Maximum concurrent connection limit
- Per-connection memory cap (maximum PDU size)
- TLS handshake timeout
- Connection idle timeout
- Database connection pool with bounded size
- Rate limiting on Bind attempts (reduces hash computation load)
- Query result size limits and query timeouts

### 7. Replication Poisoning

**Vector:** Attacker compromises the replication channel to inject malicious
identity data.

**Mitigations:**
- Mutual TLS on replication channel; both ends authenticate
- Site certificate CN validated against registered site ID
- Replication payloads include sequence numbers and integrity digests
- Anomaly detection on change set size (sudden large changes trigger alerts)
- Reconciliation process detects drift between central and site data
- Only `identity` schema data flows through replication; `runtime` is immune

## Assumptions

1. **The JIT Broker is not compromised.** If the Broker is compromised, an
   attacker can issue valid passwords for any user. Mitigation is limited to
   TTL enforcement and audit logging for post-incident forensics.

2. **TLS provides confidentiality and integrity.** The threat model assumes TLS
   is correctly implemented (via rustls) and that the configured cipher suites
   are not broken.

3. **The host operating system is hardened.** Memory zeroization only protects
   against application-level memory inspection, not a compromised kernel.

4. **PostgreSQL access controls are correctly configured.** The LDAP service
   relies on PostgreSQL role-based access control being enforced. A
   misconfigured PostgreSQL undermines many application-level controls.

5. **Clocks are approximately synchronized.** TTL enforcement on ephemeral
   passwords and replication sequence ordering assume NTP or equivalent time
   synchronization is in place at each site.

## Out-of-Scope Threats

| Threat | Reason |
|---|---|
| Compromised host OS / hypervisor | Addressed by site infrastructure hardening, not the LDAP application |
| Supply chain attack on Rust toolchain | Addressed by build pipeline controls and dependency auditing |
| Physical access to site hardware | Addressed by physical security controls at each site |
| PKI CA compromise | Addressed by CA operational security; the LDAP server trusts its configured CA |
| Side-channel attacks on hardware (Spectre, etc.) | Addressed by host OS patches and CPU microcode updates |
| Compromised client applications | The LDAP server cannot defend against a compromised client that has valid credentials |
