# NIST SP 800-53 Rev. 5 Control Mapping

This document maps NIST SP 800-53 Rev. 5 security controls to the USG JIT
LDAP Server's implementation. It serves two audiences:

1. **ATO assessors** who need to trace control requirements to specific code
   modules and verify implementation.
2. **Developers** who need to understand which controls their code implements
   and how to annotate new code.

## Applicable Control Families

| Family | ID | Name | Relevance |
|---|---|---|---|
| Access Control | AC | Access Control | Bind authentication, session management, role separation |
| Audit and Accountability | AU | Audit and Accountability | Audit logging of all operations |
| Identification and Authentication | IA | Identification and Authentication | Simple Bind, password verification, device auth |
| System and Communications Protection | SC | System and Communications Protection | TLS, cryptographic protection, session integrity |
| System and Information Integrity | SI | System and Information Integrity | Input validation, rate limiting, error handling |
| Configuration Management | CM | Configuration Management | Secure defaults, fail-closed behavior |

## Control Mapping Table

### AC — Access Control

| Control | Title | Module | Implementation Note |
|---|---|---|---|
| AC-2 | Account Management | `src/db/identity.rs`, `src/replication/puller.rs` | User accounts are managed centrally and replicated to sites. Account creation/deletion is not performed by the LDAP server; it only reads replicated account state. |
| AC-3 | Access Enforcement | `src/ldap/session.rs`, `src/ldap/bind.rs` | Session state machine enforces that only authenticated (Bound) sessions can perform Search operations. Database role permissions enforce schema-level access control. |
| AC-6 | Least Privilege | `src/db/pool.rs`, `src/db/identity.rs`, `src/db/runtime.rs` | The LDAP service uses a database role with minimum necessary permissions: SELECT on `identity`, SELECT+INSERT on `runtime`. No UPDATE/DELETE on credentials. |
| AC-7 | Unsuccessful Logon Attempts | `src/auth/rate_limit.rs` | Per-DN and per-IP rate limiting with configurable thresholds. Temporary lockout after consecutive failures. |
| AC-12 | Session Termination | `src/ldap/session.rs` | Sessions are terminated on Unbind, connection close, idle timeout, or maximum session duration. All session state is destroyed on termination. |
| AC-14 | Permitted Actions without Identification | `src/ldap/bind.rs` | Anonymous Binds are explicitly rejected. No operations are permitted without successful Bind. Only Bind and Unbind are accepted in the unauthenticated state. |
| AC-17 | Remote Access | `src/tls.rs`, `src/main.rs` | All remote access is via LDAPS (TLS-encrypted). No plaintext access path exists. |

### AU — Audit and Accountability

| Control | Title | Module | Implementation Note |
|---|---|---|---|
| AU-2 | Event Logging | `src/audit/events.rs` | Defines the set of auditable events: Bind (success/failure), Search, password issuance, session open/close, replication events, rate limit triggers. |
| AU-3 | Content of Audit Records | `src/audit/events.rs` | Each audit record includes: event type, timestamp, source IP, bound DN, operation details, result code, and session ID. |
| AU-4 | Audit Log Storage Capacity | `src/db/runtime.rs` | Audit events are stored in `runtime.audit_queue` with configurable retention. Events are forwarded to central SIEM for long-term storage. |
| AU-6 | Audit Record Review, Analysis, Reporting | `src/audit/events.rs` | Structured JSON audit events support automated analysis. Events are forwarded to SIEM for alerting and reporting. |
| AU-9 | Protection of Audit Information | `src/db/runtime.rs` | Audit queue is append-only from the LDAP service role. No DELETE permission. Database role separation prevents tampering. |
| AU-12 | Audit Record Generation | `src/audit/events.rs`, `src/ldap/session.rs`, `src/ldap/bind.rs`, `src/ldap/search.rs` | Audit events are generated at the point of each operation, before the response is sent to the client. |

### IA — Identification and Authentication

| Control | Title | Module | Implementation Note |
|---|---|---|---|
| IA-2 | Identification and Authentication | `src/ldap/bind.rs`, `src/auth/password.rs` | Users authenticate via LDAP Simple Bind with DN and password. Password is verified against the hash in `runtime.credentials`. |
| IA-3 | Device Identification and Authentication | `src/replication/puller.rs`, `src/tls.rs` | Replication channel uses mutual TLS for device-level authentication. Site certificate CN must match registered site ID. |
| IA-4 | Identifier Management | `src/db/identity.rs` | User and group identifiers (DNs) are managed centrally and replicated. The LDAP server does not create or modify identifiers. |
| IA-5 | Authenticator Management | `src/auth/password.rs`, `src/ldap/password.rs`, `src/db/runtime.rs` | Ephemeral passwords are issued by JIT Broker with TTLs. Passwords are hashed with Argon2id. Expired passwords are rejected. Password material is zeroized after use. |
| IA-5(1) | Password-Based Authentication | `src/auth/password.rs` | Passwords are stored as Argon2id hashes. Minimum complexity is enforced by the JIT Broker (not the LDAP server). TTL enforcement limits password lifetime. |
| IA-5(6) | Protection of Authenticators | `src/auth/password.rs` | Password hashes stored encrypted at rest (PostgreSQL TDE or disk encryption). In memory, password material uses `Zeroizing<T>` wrapper for zeroization on drop. |

### SC — System and Communications Protection

| Control | Title | Module | Implementation Note |
|---|---|---|---|
| SC-8 | Transmission Confidentiality and Integrity | `src/tls.rs` | All LDAP communication is encrypted via TLS 1.2+ with AEAD cipher suites. No plaintext code path. Replication uses mTLS. |
| SC-8(1) | Cryptographic Protection | `src/tls.rs` | TLS with AES-256-GCM or ChaCha20-Poly1305. Certificate-based server authentication. |
| SC-12 | Cryptographic Key Establishment | `src/tls.rs`, `src/replication/puller.rs` | TLS key exchange via ECDHE. Certificates issued by project PKI. Replication uses mutual certificate authentication. |
| SC-13 | Cryptographic Protection | `src/tls.rs`, `src/auth/password.rs` | TLS for transport. Argon2id for password hashing. SHA-256 for replication integrity. AEAD ciphers for TLS sessions. |
| SC-23 | Session Authenticity | `src/ldap/session.rs`, `src/tls.rs` | Each TLS connection has unique session state. No session tokens or cookies. Session state is per-connection and non-transferable. |
| SC-28 | Protection of Information at Rest | `src/db/runtime.rs`, `src/auth/password.rs` | Password hashes are stored in the `runtime` schema with database-level encryption. Application-level zeroization of password material in memory. |

### SI — System and Information Integrity

| Control | Title | Module | Implementation Note |
|---|---|---|---|
| SI-4 | System Monitoring | `src/auth/rate_limit.rs`, `src/audit/events.rs` | Rate limiting detects brute-force patterns. Audit events enable real-time monitoring via SIEM. Replication health metrics detect anomalies. |
| SI-10 | Information Input Validation | `src/ldap/codec.rs`, `src/ldap/session.rs` | Strict BER/ASN.1 parsing with maximum PDU size. Filter complexity limits. Parameterized SQL queries prevent injection. |

### CM — Configuration Management

| Control | Title | Module | Implementation Note |
|---|---|---|---|
| CM-6 | Configuration Settings | `src/config.rs` | Secure defaults for all security-relevant settings (TLS version, cipher suites, rate limits, timeouts). Configuration is validated at startup. |
| CM-7 | Least Functionality | `src/ldap/session.rs` | Only Bind, Search, and optionally Password Modify are implemented. No Add, Delete, Modify, ModDN, or other LDAP operations. Unsupported operations return `unwillingToPerform`. |

## Code Comment Convention

All code that implements a NIST control MUST include a comment referencing the
control ID. This enables assessors to search the codebase for control
implementations.

### Format

```rust
// NIST SP 800-53: <CONTROL-ID> — <Brief description of how this code implements the control>
```

### Examples

```rust
// NIST SP 800-53: SC-8 — All client connections are accepted only via TLS.
// There is no plaintext listener. The TcpListener is wrapped in TlsAcceptor
// before any LDAP processing occurs.
let tls_acceptor = TlsAcceptor::from(tls_config);
let tls_stream = tls_acceptor.accept(tcp_stream).await?;
```

```rust
// NIST SP 800-53: AC-7 — Rate limiter checks are performed before password
// hash retrieval to prevent CPU exhaustion from brute-force attempts.
if !rate_limiter.check(bind_dn, source_ip) {
    audit.emit(Event::bind_rate_limited(bind_dn, source_ip));
    return Err(LdapError::UnwillingToPerform);
}
```

```rust
// NIST SP 800-53: IA-5(6) — Password bytes are held in a Zeroizing wrapper.
// When this variable is dropped, the underlying memory is overwritten with
// zeros, preventing password material from lingering in process memory.
let password: Zeroizing<Vec<u8>> = Zeroizing::new(bind_request.password().to_vec());
```

```rust
// NIST SP 800-53: AU-12 — Audit event is emitted before the Bind response
// is sent, ensuring the event is recorded even if the connection drops
// immediately after the response.
audit.emit(Event::bind_success(session.bound_dn(), source_ip));
```

```rust
// NIST SP 800-53: AC-14 — Anonymous Binds (empty DN or empty password) are
// explicitly rejected. No directory data is accessible without authentication.
if bind_dn.is_empty() || password.is_empty() {
    audit.emit(Event::bind_anonymous_rejected(source_ip));
    return Err(LdapError::UnwillingToPerform);
}
```

### Rules for Control Comments

1. **Place the comment immediately above the code it describes.** Not in a
   separate file, not at the top of the module (unless the entire module
   implements a single control).

2. **Be specific.** State what the code does for the control, not just the
   control name. "SC-8" alone is insufficient; "SC-8 — TLS is required for
   all connections" is correct.

3. **One comment per control point.** If a single function implements multiple
   controls, use multiple comments.

4. **Keep comments current.** If the implementation changes, update the control
   comment. Stale control comments are worse than no comments.

## How Assessors Should Use These Mappings

### Traceability Workflow

1. **Start with a control.** Find the control ID in the mapping table above.
   Note the module path.

2. **Open the module.** Search for `NIST SP 800-53: <CONTROL-ID>` in the
   source file.

3. **Read the implementation.** The comment explains what the code does for the
   control. The code immediately below implements it.

4. **Verify the invariant.** Cross-reference with the
   [Security Invariants](security-invariants.md) document for the behavioral
   guarantee.

5. **Check the test.** Look for test functions that exercise the control's
   behavior (e.g., `test_anonymous_bind_rejected` for AC-14).

### Searching the Codebase

```bash
# Find all implementations of a specific control
grep -rn "NIST SP 800-53: AC-7" src/

# Find all NIST control comments
grep -rn "NIST SP 800-53:" src/

# Count controls implemented per module
grep -rn "NIST SP 800-53:" src/ | cut -d: -f1 | sort | uniq -c | sort -rn
```

### What Assessors Should NOT Expect

- Not every line of code has a control comment. Only security-relevant code
  that directly implements a control behavior is annotated.
- The LDAP server does not implement every sub-control. Some controls (e.g.,
  AC-2 account management) are primarily implemented by the central identity
  management system, not the LDAP server. The LDAP server's role is noted.
- Controls related to operational procedures (e.g., IR incident response) are
  not implemented in code. They are addressed in operational documentation.
