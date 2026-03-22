# USG JIT LDAP Server

A minimal, security-focused LDAP server in Rust designed for JIT (Just-In-Time) password broker environments.

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/192d-Wing/usg-jit-ldap-server/ci.yml?style=for-the-badge&logo=github)](https://github.com/192d-Wing/usg-jit-ldap-server/actions/workflows/ci.yml)

## Overview

This is **not** a general-purpose LDAP server. It is a narrow, production-defensible LDAPS service built for environments where:

- An external JIT Broker issues ephemeral passwords
- Identity data (users/groups) replicates across 184 geographically distributed sites
- Password material is **never** replicated — it remains site-local
- TLS is mandatory from connection open (LDAPS on 636 only)
- The system must support ATO (Authority to Operate) with NIST SP 800-53 Rev. 5 control mappings

## Hard Constraints

| Constraint | Detail |
| --- | --- |
| **Protocol** | LDAPS only (port 636). No LDAP/389. No StartTLS. |
| **Operations** | Bind, Search, optional Password Modify extended op |
| **Datastore** | PostgreSQL only |
| **Replication** | Identity data only. No password/credential replication. |
| **Sites** | 184 locations, hub-and-spoke topology |
| **Security** | Fail-closed. TLS required. Rate-limited. Audited. |
| **Compliance** | NIST SP 800-53 Rev. 5 control mappings in code comments |

## Architecture

```text
┌─────────────────────────────────────────────────┐
│                  Central Hub                    │
│  ┌─────────────┐  ┌──────────────────────────┐  │
│  │Control Plane│  │ PostgreSQL (Primary)     │  │
│  │ (Admin API) │  │  - identity schema       │  │
│  │             │  │  - replication metadata  │  │
│  └─────────────┘  └──────────────────────────┘  │
└────────────────────────┬────────────────────────┘
                         │ Replication (identity only)
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
   ┌───────────┐   ┌───────────┐   ┌───────────┐
   │  Site A   │   │  Site B   │   │  Site N   │
   │ ┌───────┐ │   │ ┌───────┐ │   │ ┌───────┐ │
   │ │LDAPS  │ │   │ │LDAPS  │ │   │ │LDAPS  │ │
   │ │:636   │ │   │ │:636   │ │   │ │:636   │ │
   │ └───┬───┘ │   │ └───┬───┘ │   │ └───┬───┘ │
   │ ┌───┴───┐ │   │ ┌───┴───┐ │   │ ┌───┴───┐ │
   │ │  PG   │ │   │ │  PG   │ │   │ │  PG   │ │
   │ │local+ │ │   │ │local+ │ │   │ │local+ │ │
   │ │replica│ │   │ │replica│ │   │ │replica│ │
   │ └───────┘ │   │ └───────┘ │   │ └───────┘ │
   └───────────┘   └───────────┘   └───────────┘
```

## LDAPv3 Scope (v1)

| Operation | Status |
| --- | --- |
| Simple Bind | Supported |
| Search | Supported |
| Password Modify ExtOp | Optional (broker integration) |
| Anonymous Bind | Rejected |
| SASL | Not implemented |
| StartTLS | Explicitly rejected |
| Add/Delete/Modify | Not implemented |
| Referrals | Not implemented |

## Database Design

Two logical schemas per site:

- **`identity`** — replicated from central: users, groups, memberships, sites
- **`runtime`** — site-local only: ephemeral passwords, bind events, audit queue

Password hashes live exclusively in `runtime` and are never replicated.

## Development

```bash
# Prerequisites
# - Rust 1.75+
# - PostgreSQL 15+
# - TLS certificates for local dev

cargo build
cargo test
cargo run -- --config config.toml
```

## Project Structure

```text
src/
├── main.rs              # Entry point, TLS listener setup
├── config.rs            # Configuration loading and validation
├── ldap/
│   ├── mod.rs           # LDAP module root
│   ├── codec.rs         # BER/ASN.1 encoding/decoding
│   ├── session.rs       # Connection session state machine
│   ├── bind.rs          # Bind operation handler
│   ├── search.rs        # Search operation handler
│   └── password.rs      # Password Modify extended operation
├── db/
│   ├── mod.rs           # Database module root
│   ├── pool.rs          # Connection pool management
│   ├── identity.rs      # Identity schema repository
│   └── runtime.rs       # Runtime schema repository
├── auth/
│   ├── mod.rs           # Auth module root
│   ├── password.rs      # Password verification + zeroization
│   └── rate_limit.rs    # Bind rate limiting
├── replication/
│   ├── mod.rs           # Replication module root
│   ├── puller.rs        # Identity data pull from central
│   └── health.rs        # Replication health tracking
├── audit/
│   ├── mod.rs           # Audit module root
│   └── events.rs        # Structured audit event emission
└── tls.rs               # TLS configuration and enforcement
```

## Security Model

- **Fail-closed**: If TLS material is unavailable, the server does not start.
- **No plaintext**: There is no code path that accepts unencrypted LDAP.
- **Ephemeral passwords**: Issued by JIT Broker, stored locally, never replicated.
- **Rate limiting**: Per-DN and per-source-IP bind attempt throttling.
- **Audit logging**: All bind attempts, search operations, and administrative actions.
- **Zeroization**: Password material is zeroized in memory after use.

## Compliance

Code comments include NIST SP 800-53 Rev. 5 control mappings where architecturally relevant. These are written for assessors and maintainers, not as decoration.

## License

Apache 2.0
