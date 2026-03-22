# Security Invariants

This document defines the non-negotiable security properties of the USG JIT
LDAP Server. These invariants must hold at all times, in all configurations,
across all 184 sites. Any code change that violates an invariant is a
security defect.

## Invariant 1: TLS Is Mandatory

**Statement:** There is no code path that accepts a plaintext LDAP connection.

**Implementation:**
- The server listens exclusively on port 636 (LDAPS).
- Port 389 is never opened. There is no configuration option to enable it.
- The `TcpListener` is wrapped in a `TlsAcceptor` before any LDAP processing
  occurs. Raw TCP connections that fail TLS negotiation are dropped.
- There is no StartTLS implementation. The `ExtendedRequest` handler does not
  recognize the StartTLS OID.
- TLS version minimum is 1.3. TLS 1.0, 1.1, and 1.2 are not supported.

**Verification:** Attempting to connect on port 636 without TLS produces a
connection reset. There is no port 389 listener. Code review confirms no
`TcpStream` is used without `TlsAcceptor`.

**NIST Controls:** SC-8, SC-13, SC-23

---

## Invariant 2: Passwords Never Leave a Site

**Statement:** Password hashes stored in the `runtime.credentials` table are
never included in replication, never returned in Search results, and never
transmitted outside the site boundary.

**Implementation:**
- Password hashes are stored in the `runtime` schema, which is entirely
  excluded from the replication protocol.
- Replication queries only read from the `identity` schema. The puller has
  no `SELECT` permission on `runtime.credentials`.
- Search operations query only the `identity` schema. The Search handler has
  no code path that reads from `runtime`.
- The `runtime.credentials` table is not referenced by any replication or
  export function.

**Verification:** Code search for any query against `runtime.credentials`
outside of the Bind verification path and JIT Broker issuance path. Database
role permissions confirm the replication role has no access to `runtime`.

**NIST Controls:** IA-5(6), SC-28

---

## Invariant 3: Password Material Is Zeroized After Use

**Statement:** After password verification completes (success or failure), the
plaintext password bytes and any intermediate hash material are overwritten
with zeros in memory.

**Implementation:**
- Password bytes received from the Bind PDU are stored in a `Zeroizing<Vec<u8>>`
  wrapper (from the `zeroize` crate).
- When the `Zeroizing` wrapper is dropped, the underlying memory is overwritten
  with zeros.
- Intermediate hash computation buffers are similarly wrapped.
- The password is not logged, not included in error messages, and not stored
  in any struct that outlives the Bind operation.

**Verification:** Code review confirms all password-holding variables use
`Zeroizing<T>` or implement `ZeroizeOnDrop`. No password bytes are copied
to unprotected buffers. Audit log events contain the DN but never the password.

**NIST Controls:** IA-5(6), SC-28

---

## Invariant 4: Bind Attempts Are Rate-Limited

**Statement:** The rate of Bind attempts is limited per DN and per source IP
address. Excess attempts are rejected before hash computation occurs.

**Implementation:**
- The rate limiter maintains sliding-window counters for each DN and each
  source IP.
- When a Bind request arrives, the rate limiter is checked BEFORE the password
  hash is retrieved or computed.
- If either limit is exceeded, the Bind is rejected with
  `resultCode: unwillingToPerform` and an audit event is emitted.
- Rate limit thresholds are configurable but have secure defaults:
  - Per-DN: 5 attempts per 60 seconds
  - Per-IP: 20 attempts per 60 seconds
- After a configurable lockout threshold (e.g., 10 consecutive failures), the
  DN is temporarily locked for a configurable duration.

**Verification:** Load test with rapid Bind attempts confirms rejection after
threshold. Code review confirms rate check precedes hash computation.

**NIST Controls:** AC-7, SI-4

---

## Invariant 5: All Operations Are Audit-Logged

**Statement:** Every Bind attempt (success or failure), every Search operation,
every password issuance, every session open/close, and every replication event
produces a structured audit record.

**Implementation:**
- The audit module is called from every operation handler before returning a
  response to the client.
- Audit events are written to both `runtime.audit_queue` (for durability) and
  structured log output (for real-time visibility).
- Audit events include: event type, timestamp, source IP, bound DN (if
  applicable), operation details, and result.
- Audit logging failure is treated as a degraded state. The operation still
  completes (to preserve availability), but a metric is incremented and an
  alert is triggered.

**Verification:** Code review confirms every operation handler calls the audit
module. Integration tests verify that each operation type produces the expected
audit event.

**NIST Controls:** AU-2, AU-3, AU-6, AU-12

---

## Invariant 6: Service Fails Closed on TLS Material Unavailability

**Statement:** If TLS certificate or private key material is unavailable,
corrupted, or expired at startup, the server refuses to start. If TLS material
becomes unusable at runtime, the server stops accepting new connections.

**Implementation:**
- At startup, the server loads the TLS certificate chain and private key. If
  loading fails, the process exits with a non-zero exit code and an error log.
- Certificate validity (not-before, not-after) is checked at load time. An
  expired certificate prevents startup.
- At runtime, if the `TlsAcceptor` encounters an error that indicates TLS
  material is no longer valid (e.g., after a hot-reload attempt with a bad
  cert), the listener stops accepting new connections and logs a critical error.
- There is no fallback to plaintext. There is no "degraded mode" without TLS.

**Verification:** Remove or corrupt the certificate file and attempt to start
the server. Confirm it exits with an error. At runtime, replace the cert with
an invalid one and trigger reload. Confirm new connections are refused.

**NIST Controls:** SC-8, SC-13, CM-6

---

## Invariant 7: Replication Channel Is Mutually Authenticated

**Statement:** The replication channel between the central hub and each site
uses mutual TLS. Both ends must present valid certificates.

**Implementation:**
- The site's replication puller connects to the central hub over TLS and
  presents the site's client certificate.
- The central hub validates the site's certificate against the project CA and
  checks that the certificate CN matches a registered site ID.
- The site validates the hub's server certificate against the project CA.
- If either certificate validation fails, the connection is refused and the
  replication pull fails (with an audit event).

**Verification:** Attempt replication with an invalid site certificate. Confirm
connection is refused. Attempt with an invalid hub certificate. Confirm the
site rejects the connection.

**NIST Controls:** IA-3, SC-8, SC-12

---

## Invariant 8: No Anonymous Binds Permitted

**Statement:** Anonymous Bind requests (empty DN and empty password) are
explicitly rejected. No directory data is accessible without authentication.

**Implementation:**
- The Bind handler checks for empty DN or empty password as the first
  validation step.
- If either is empty, the Bind is rejected with
  `resultCode: unwillingToPerform`.
- The session remains in the `Unauthenticated` state. No Search or other data
  operations are permitted.
- An audit event is emitted for the rejected anonymous Bind attempt.

**Verification:** Send a Bind request with empty DN and empty password. Confirm
rejection. Send a Search request without a preceding successful Bind. Confirm
rejection.

**NIST Controls:** AC-14, IA-2

---

## Invariant 9: Session State Is Per-Connection, Not Shared

**Statement:** Each TLS connection has its own independent session state. No
session state is shared between connections, and there is no session
resumption or transfer mechanism.

**Implementation:**
- Session state (authentication status, bound DN, rate limit counters) is
  stored in a per-connection struct that is created when the TLS connection is
  accepted and dropped when the connection closes.
- There is no session token, cookie, or identifier that could be transferred
  between connections.
- The session struct is not stored in any shared data structure that other
  connections can access.
- Connection close (graceful or abrupt) destroys all session state.

**Verification:** Authenticate on connection A. Open connection B. Confirm
connection B is in the Unauthenticated state. Close connection A. Confirm its
session state is dropped (observable via metrics showing active session count
decrement).

**NIST Controls:** SC-23, AC-12

---

## Invariant Summary Table

| # | Invariant | Key Controls | Failure Mode |
|---|---|---|---|
| 1 | TLS is mandatory | SC-8, SC-13 | Refuse connection |
| 2 | Passwords never leave a site | IA-5(6), SC-28 | Schema/role enforcement |
| 3 | Password material is zeroized | IA-5(6), SC-28 | Zeroize on drop |
| 4 | Bind attempts are rate-limited | AC-7, SI-4 | Reject with unwillingToPerform |
| 5 | All operations are audit-logged | AU-2, AU-3, AU-12 | Degraded state + alert |
| 6 | Fail closed on TLS unavailability | SC-8, CM-6 | Refuse to start / stop accepting |
| 7 | Replication is mutually authenticated | IA-3, SC-8 | Refuse connection |
| 8 | No anonymous binds | AC-14, IA-2 | Reject Bind |
| 9 | Session state is per-connection | SC-23, AC-12 | State dropped on close |
