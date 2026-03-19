# ADR-002: PostgreSQL as Sole Datastore

**Status:** Accepted

**Date:** 2026-03-19

## Context

The LDAP server needs persistent storage for:

1. **Identity data** (users, groups, memberships) — replicated from central.
2. **Credential data** (ephemeral password hashes) — site-local, written by
   JIT Broker.
3. **Runtime data** (bind events, audit queue, replication health) — site-local.

Traditional LDAP servers use purpose-built directory databases (BDB, LMDB, or
custom B-tree stores). Alternatives considered:

- **Embedded database (SQLite, LMDB):** Lower operational overhead for a
  single-purpose server, but lacks the rich access control, replication
  primitives, and operational tooling that PostgreSQL provides.
- **Multiple datastores (e.g., Redis for rate limiting + PostgreSQL for
  identity):** Adds operational complexity and failure modes. Each additional
  datastore is another component to patch, monitor, and secure.
- **PostgreSQL:** Already present in the operational environment for other
  services. Well-understood by site operations teams. Provides schema
  separation, role-based access control, row-level security, and mature
  replication mechanisms.

Key factors:

- 184 sites already run PostgreSQL for other services. Operations teams have
  existing expertise, monitoring, backup procedures, and patch processes.
- Schema separation (identity vs. runtime) maps naturally to PostgreSQL
  schemas with per-schema role permissions.
- PostgreSQL's row-level security provides defense-in-depth for credential
  isolation.
- The LDAP server's query patterns are simple (key lookups, filtered scans).
  No complex joins or analytics.

## Decision

PostgreSQL is the sole datastore for the LDAP server. Both the `identity`
schema (replicated) and the `runtime` schema (site-local) reside in the same
PostgreSQL instance at each site.

Rate limiting state is held in-memory (with optional persistence to
`runtime.rate_limits` for warm restart).

## Consequences

### Positive

- **Single operational dependency.** One database to monitor, patch, back up,
  and secure per site.
- **Leverages existing infrastructure.** Sites already run PostgreSQL.
  Operations teams do not need to learn a new database.
- **Strong access control.** PostgreSQL roles + schema permissions + row-level
  security enforce the separation between identity data, credentials, and
  audit records.
- **Schema separation is native.** The `identity` and `runtime` schemas are
  first-class PostgreSQL constructs with independent permissions.
- **Mature tooling.** pg_dump, pg_stat, pgBouncer, and standard monitoring
  integrations are available.
- **Assessor-friendly.** PostgreSQL's security model is well-documented and
  understood by security auditors.

### Negative

- **PostgreSQL is a large dependency.** The LDAP server is a lightweight Rust
  process, but it requires a running PostgreSQL instance. This is mitigated by
  PostgreSQL already being present at each site.
- **Latency for Bind operations.** Each Bind requires a database query for the
  password hash. This is acceptable given the expected Bind rate (low hundreds
  per minute per site) and local PostgreSQL access (sub-millisecond on Unix
  socket).
- **No offline mode.** If PostgreSQL is down, the LDAP server cannot serve
  requests. This is acceptable because PostgreSQL downtime is a site-level
  infrastructure failure, not specific to the LDAP server.

### Neutral

- Connection pooling (via `deadpool-postgres` or `bb8`) manages database
  connection lifecycle efficiently.
- The PostgreSQL version requirement (15+) aligns with the versions already
  deployed at sites.
