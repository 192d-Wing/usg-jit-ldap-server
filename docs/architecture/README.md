# USG JIT LDAP Server — System Architecture

## Overview

The USG JIT LDAP Server is a purpose-built, minimal LDAP directory service
designed for a JIT (Just-In-Time) password broker environment spanning 184
geographically distributed sites. It provides LDAPS-only identity lookups and
Simple Bind authentication against a PostgreSQL backend. An external JIT Broker
issues ephemeral passwords that are stored site-locally and never replicated.

This document describes the high-level architecture, component inventory, trust
boundaries, and design rationale.

## High-Level Component Diagram

```
                    ┌──────────────────────────────────────────┐
                    │            CENTRAL HUB                    │
                    │                                          │
                    │  ┌────────────────┐  ┌───────────────┐  │
                    │  │ Control Plane  │  │  PostgreSQL    │  │
                    │  │  - Admin API   │  │  (Primary)     │  │
                    │  │  - Site mgmt   │  │  - identity.*  │  │
                    │  │  - Policy cfg  │  │  - repl_meta.* │  │
                    │  └────────────────┘  └───────┬───────┘  │
                    │                              │          │
                    └──────────────────────────────┼──────────┘
                                                   │
                           Replication Channel      │  (mTLS, identity-only)
                      ┌────────────────────────────┤
                      │            │               │
              ┌───────▼──┐  ┌─────▼────┐    ┌─────▼────┐
              │  SITE A  │  │  SITE B  │    │ SITE 184 │
              │          │  │          │    │          │
              │ ┌──────┐ │  │ ┌──────┐ │    │ ┌──────┐ │
              │ │LDAPS │ │  │ │LDAPS │ │    │ │LDAPS │ │
              │ │ :636 │ │  │ │ :636 │ │    │ │ :636 │ │
              │ └──┬───┘ │  │ └──┬───┘ │    │ └──┬───┘ │
              │    │     │  │    │     │    │    │     │
              │ ┌──▼───┐ │  │ ┌──▼───┐ │    │ ┌──▼───┐ │
              │ │Sessn │ │  │ │Sessn │ │    │ │Sessn │ │
              │ │Hndlr │ │  │ │Hndlr │ │    │ │Hndlr │ │
              │ └──┬───┘ │  │ └──┬───┘ │    │ └──┬───┘ │
              │    │     │  │    │     │    │    │     │
              │ ┌──▼───────────────────┐ │  │          │
              │ │  PostgreSQL (Local)  │ │  │   ...    │
              │ │  ┌────────────────┐  │ │  │          │
              │ │  │identity schema │  │ │  │          │
              │ │  │ (replicated)   │  │ │  │          │
              │ │  ├────────────────┤  │ │  │          │
              │ │  │runtime schema  │  │ │  │          │
              │ │  │ (site-local)   │  │ │  │          │
              │ │  └────────────────┘  │ │  │          │
              │ └──────────────────────┘ │  │          │
              │                          │  │          │
              │  ┌─────────┐ ┌────────┐  │  │          │
              │  │  Audit  │ │  JIT   │  │  │          │
              │  │  Queue  │ │ Broker │  │  │          │
              │  └─────────┘ │ Client │  │  │          │
              │              └────────┘  │  │          │
              └──────────────────────────┘  └──────────┘
```

## Control Plane vs. Data Plane

### Control Plane (Central Hub)

The central hub is the authoritative source for identity data and site policy.
It does NOT serve LDAP queries to end users. Its responsibilities:

- **Identity management**: Authoritatively stores users, groups, group
  memberships, and site-to-user assignments.
- **Replication orchestration**: Publishes identity change sets that sites pull.
- **Site management**: Registers sites, issues replication credentials,
  maintains site health metadata.
- **Policy distribution**: Pushes site-level configuration (rate limits,
  password policy parameters, enabled operations).

### Data Plane (184 Sites)

Each site is an independent LDAP service node. Sites:

- **Serve LDAPS traffic** on port 636 to local clients.
- **Handle Bind operations** by verifying ephemeral passwords in the local
  runtime schema.
- **Handle Search operations** by querying the local identity schema.
- **Accept password issuance** from the JIT Broker (via ExtOp or direct DB
  write).
- **Pull identity updates** from the central hub on a schedule.
- **Operate autonomously** during WAN outages using locally cached identity
  data and locally stored credentials.

## Trust Boundary Definitions

See [trust-boundaries.md](trust-boundaries.md) for the full trust boundary
analysis. In summary, the system defines six trust boundaries:

1. **External client to LDAPS listener** — untrusted network boundary
2. **LDAPS listener to session handler** — post-TLS, pre-authentication
3. **Session handler to PostgreSQL** — internal, trusted
4. **Central hub to site replication channel** — mutually authenticated
5. **JIT Broker to password issuance** — authenticated and authorized
6. **Site LDAP service to local runtime DB** — internal, trusted

## LDAPS-Only Design Rationale

This server accepts connections exclusively via LDAPS (TLS-first on port 636).
The following alternatives were evaluated and rejected:

| Alternative | Rejection Reason |
|---|---|
| LDAP on 389 + StartTLS | StartTLS upgrade is susceptible to stripping attacks; clients may accidentally send credentials before TLS is established. Adds code complexity for the upgrade state machine. |
| LDAP on 389 (cleartext) | Fundamentally incompatible with ATO requirements. Password material would traverse the network in plaintext. |
| Dual-port (636 + 389) | Increases attack surface with no benefit. Every client in this environment supports LDAPS. |

By supporting only LDAPS, we eliminate an entire class of configuration errors
and downgrade attacks. See [ADR-001](decisions/adr-001-ldaps-only.md).

## Component Inventory

| Component | Module Path | Responsibility |
|---|---|---|
| **TLS Listener** | `src/tls.rs`, `src/main.rs` | Accept TLS connections on :636, enforce certificate requirements, reject non-TLS |
| **LDAP Codec** | `src/ldap/codec.rs` | BER/ASN.1 encoding and decoding of LDAPv3 PDUs |
| **Session Handler** | `src/ldap/session.rs` | Per-connection state machine: unauthenticated → bound → closed |
| **Bind Handler** | `src/ldap/bind.rs` | Process Simple Bind requests, delegate to password verification |
| **Search Handler** | `src/ldap/search.rs` | Process Search requests against identity schema |
| **Password Modify** | `src/ldap/password.rs` | Optional Password Modify extended operation for JIT Broker |
| **Password Verification** | `src/auth/password.rs` | Hash comparison with zeroization of sensitive material |
| **Rate Limiter** | `src/auth/rate_limit.rs` | Per-DN and per-IP bind attempt throttling |
| **DB Pool** | `src/db/pool.rs` | PostgreSQL connection pooling |
| **Identity Repository** | `src/db/identity.rs` | Read-only queries against the identity schema |
| **Runtime Repository** | `src/db/runtime.rs` | Read/write against the runtime schema (passwords, bind events) |
| **Replication Puller** | `src/replication/puller.rs` | Pull identity change sets from central hub |
| **Replication Health** | `src/replication/health.rs` | Track replica freshness, detect staleness |
| **Audit Events** | `src/audit/events.rs` | Structured audit event creation and emission |
| **Configuration** | `src/config.rs` | Load and validate TOML configuration |

## Key Design Principles

1. **Minimal surface area**: Only implement Bind, Search, and optionally
   Password Modify. No Add/Delete/Modify/ModDN.
2. **Fail closed**: If any security-critical resource is unavailable (TLS
   certs, database), the server refuses to start or shuts down.
3. **Local survivability**: Each site operates independently when the WAN is
   down. Identity data is cached locally; passwords are always local.
4. **Audit everything**: Every Bind attempt, Search operation, and password
   issuance is logged as a structured audit event.
5. **Assessor-friendly**: Code comments map to NIST SP 800-53 Rev. 5 controls
   so ATO assessors can trace requirements to implementation.

## Related Documents

- [Trust Boundaries](trust-boundaries.md)
- [Threat Model](threat-model.md)
- [Replication Topology](replication-topology.md)
- [Data Flow](data-flow.md)
- [Security Invariants](security-invariants.md)
- [NIST Control Mapping](nist-control-mapping.md)
- [Architecture Decision Records](decisions/)
