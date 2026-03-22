# Trust Boundaries

This document defines all trust boundaries in the USG JIT LDAP Server system.
Each boundary represents a transition between security domains with different
trust levels, authentication requirements, and access controls.

## Trust Boundary Diagram

```
 UNTRUSTED                         SITE BOUNDARY
 NETWORK                    ┌──────────────────────────────────────────────┐
                            │                                              │
  ┌──────────┐   TLS (1)   │  ┌──────────────┐   (2)   ┌──────────────┐  │
  │  LDAP    │─────────────►│──│ LDAPS        │────────►│   Session    │  │
  │  Client  │  (untrusted) │  │ Listener     │ (authn  │   Handler    │  │
  │          │◄─────────────│──│ :636         │  reqd)  │              │  │
  └──────────┘              │  └──────────────┘         └──────┬───────┘  │
                            │                                  │          │
                            │                           (3)    │ (trusted │
                            │                                  │  local)  │
                            │                           ┌──────▼───────┐  │
                            │                           │  PostgreSQL  │  │
                            │                           │  ┌─────────┐ │  │
                            │                           │  │identity │ │  │
                            │                           │  │ schema  │ │  │
                            │                           │  ├─────────┤ │  │
                            │                           │  │runtime  │ │  │
                            │  (6) trusted local        │  │ schema  │ │  │
                            │  ┌──────────────┐         │  └─────────┘ │  │
                            │  │ LDAP Service │────────►│              │  │
                            │  │ (runtime)    │         └──────────────┘  │
                            │  └──────────────┘                │          │
                            │                                  │          │
                            └──────────────────────────────────┼──────────┘
                                                               │
  ┌──────────┐   mTLS (4)                                      │
  │ Central  │─────────────────────────────────────────────────┘
  │ Hub      │   (mutually authenticated replication)
  └──────────┘

  ┌──────────┐   mTLS (5)    ┌──────────────┐
  │   JIT    │──────────────►│ Password     │
  │  Broker  │ (authn+authz) │ Issuance API │
  └──────────┘               └──────────────┘
```

## Boundary Definitions

### Boundary 1: External Client to LDAPS Listener

| Property | Value |
|---|---|
| **Source** | LDAP client (PAM, application, SSH, etc.) |
| **Destination** | LDAPS listener on port 636 |
| **Trust Level** | Untrusted |
| **Transport** | TLS 1.3 only |
| **Authentication** | None at this boundary; TLS handshake only |
| **Authorization** | None; any network peer may attempt a connection |

**Controls at this boundary:**

- TLS is mandatory. There is no plaintext code path. If TLS negotiation fails,
  the connection is dropped immediately.
- Server presents a valid TLS certificate. Client certificate authentication
  is not required for LDAP clients (Simple Bind is used instead).
- Connection rate limiting may be applied at the listener level to defend
  against SYN floods or TLS exhaustion.
- Cipher suite is restricted to AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305).
- The listener does not advertise supported operations or server capabilities
  until TLS is established.

**NIST Controls:** SC-8 (Transmission Confidentiality), SC-13 (Cryptographic
Protection), SC-23 (Session Authenticity)

### Boundary 2: LDAPS Listener to Session Handler

| Property | Value |
|---|---|
| **Source** | LDAPS listener (post-TLS handshake) |
| **Destination** | Session handler (per-connection state machine) |
| **Trust Level** | Partially trusted (TLS established, identity unverified) |
| **Transport** | In-process (Rust async task boundary) |
| **Authentication** | Required before any data operation; Bind must succeed first |
| **Authorization** | Bind DN determines operation scope |

**Controls at this boundary:**

- Session starts in the `Unauthenticated` state. Only Bind and Unbind
  operations are accepted in this state.
- A successful Bind transitions the session to `Bound`. Search operations
  are only permitted in the `Bound` state.
- Failed Bind attempts increment rate-limiting counters (per-DN, per-source-IP).
- After a configurable number of failed Binds, the connection is closed.
- Anonymous Binds (empty DN + empty password) are explicitly rejected.
- The session handler enforces a maximum PDU size to prevent memory exhaustion.

**NIST Controls:** IA-2 (Identification and Authentication), IA-5 (Authenticator
Management), AC-7 (Unsuccessful Logon Attempts)

### Boundary 3: Session Handler to PostgreSQL

| Property | Value |
|---|---|
| **Source** | Session handler (authenticated session) |
| **Destination** | PostgreSQL database (local) |
| **Trust Level** | Internal trusted |
| **Transport** | Unix socket or localhost TCP (optionally TLS) |
| **Authentication** | PostgreSQL role credentials (configured at startup) |
| **Authorization** | Database role has restricted permissions per schema |

**Controls at this boundary:**

- The LDAP service connects to PostgreSQL using a dedicated database role with
  minimum necessary privileges.
- For the `identity` schema: `SELECT` only. The LDAP service never writes
  identity data; that is the replication puller's job.
- For the `runtime` schema: `SELECT` and `INSERT` (for password verification
  lookups and bind event logging). `UPDATE` for password state changes is
  restricted to the JIT Broker's dedicated role.
- Connection pooling limits the number of concurrent database connections.
- SQL queries use parameterized statements exclusively; no string interpolation.

**NIST Controls:** AC-3 (Access Enforcement), AC-6 (Least Privilege),
SC-28 (Protection of Information at Rest)

### Boundary 4: Central Hub to Site Replication Channel

| Property | Value |
|---|---|
| **Source** | Central hub PostgreSQL (primary) |
| **Destination** | Site PostgreSQL (replica identity schema) |
| **Trust Level** | Mutually authenticated |
| **Transport** | TLS with mutual certificate authentication (mTLS) |
| **Authentication** | Both ends present certificates issued by the project CA |
| **Authorization** | Site certificate CN must match the registered site ID |

**Controls at this boundary:**

- Replication uses mutual TLS. Both the central hub and the site must present
  valid certificates.
- The site's certificate subject must match a registered site identifier in
  the central hub's site registry.
- Only identity-scoped data transits this boundary: users, groups, group
  memberships, site assignments, and directory policies.
- Password hashes, bind events, audit records, and runtime state NEVER cross
  this boundary. This is enforced at the schema level — replication queries
  only read from the `identity` schema.
- The replication protocol is pull-based: sites initiate connections to the
  central hub. The hub never pushes to sites.
- Each replication payload includes a monotonic sequence number for ordering
  and a SHA-256 digest for integrity verification.

**NIST Controls:** SC-8 (Transmission Confidentiality), IA-3 (Device
Identification and Authentication), SC-12 (Cryptographic Key Establishment)

### Boundary 5: JIT Broker to Password Issuance API

| Property | Value |
|---|---|
| **Source** | External JIT Broker service |
| **Destination** | Password issuance endpoint (ExtOp or direct DB API) |
| **Trust Level** | Authenticated and authorized |
| **Transport** | TLS (LDAPS ExtOp) or mTLS (direct DB connection) |
| **Authentication** | Service credential (certificate or token) |
| **Authorization** | Broker role authorized exclusively for password writes |

**Controls at this boundary:**

- The JIT Broker is the only entity authorized to write password hashes to the
  runtime schema.
- If using the Password Modify extended operation, the Broker must Bind with a
  designated service DN that has the `password-issuer` role.
- If using direct database access, the Broker connects with a dedicated
  PostgreSQL role that has `INSERT`/`UPDATE` on `runtime.credentials` only.
- Issued passwords include a TTL (time-to-live). Expired passwords are rejected
  during Bind verification.
- The Broker's issuance events are audit-logged with the Broker's identity,
  the target user DN, the TTL, and a timestamp.
- The LDAP service itself never generates passwords. It only verifies them.

**NIST Controls:** IA-5 (Authenticator Management), IA-4 (Identifier
Management), AC-2 (Account Management)

### Boundary 6: Site LDAP Service to Local Runtime DB

| Property | Value |
|---|---|
| **Source** | LDAP service process |
| **Destination** | Local PostgreSQL runtime schema |
| **Trust Level** | Internal trusted |
| **Transport** | Unix socket (preferred) or localhost TCP |
| **Authentication** | PostgreSQL role credentials |
| **Authorization** | Role-specific permissions per table |

**Controls at this boundary:**

- The runtime schema contains sensitive material: password hashes, bind event
  logs, and audit queue entries.
- The LDAP service role can `SELECT` from `runtime.credentials` (for password
  verification) and `INSERT` into `runtime.bind_events` and
  `runtime.audit_queue`.
- The LDAP service role cannot `UPDATE` or `DELETE` credentials. Only the JIT
  Broker's role and a dedicated maintenance role can modify credentials.
- Audit queue entries are append-only from the LDAP service's perspective.
- The runtime schema is never included in replication exports.
- Database-level row security policies enforce that the LDAP service role
  cannot read credentials for DNs outside the local site scope (defense in
  depth for misconfiguration).

**NIST Controls:** AC-3 (Access Enforcement), AC-6 (Least Privilege),
AU-9 (Protection of Audit Information)

## Trust Assumptions

1. **PostgreSQL is trusted infrastructure.** The local PostgreSQL instance is
   assumed to be correctly configured, patched, and access-controlled. The LDAP
   service does not attempt to defend against a compromised PostgreSQL.

2. **TLS certificates are valid.** The service trusts its own certificate and
   the CA chain. Certificate provisioning and rotation are handled by external
   PKI infrastructure.

3. **The JIT Broker is honest.** The LDAP service trusts that the JIT Broker
   issues passwords only for legitimate access requests. The service enforces
   TTLs and audit logging but does not second-guess issuance decisions.

4. **The host OS is not compromised.** Memory safety of password material
   relies on the OS process isolation. A compromised host negates all
   application-level protections.

5. **DNS and network routing are correct within the site.** The LDAP service
   trusts that localhost connections to PostgreSQL reach the actual local
   PostgreSQL instance.
