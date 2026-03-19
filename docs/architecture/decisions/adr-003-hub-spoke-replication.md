# ADR-003: Hub-and-Spoke Replication with Identity-Only Scope

**Status:** Accepted

**Date:** 2026-03-19

## Context

The system serves 184 geographically distributed sites. Each site needs a local
copy of identity data (users, groups, memberships) to serve LDAP queries
without depending on WAN connectivity.

Replication design options considered:

1. **PostgreSQL native logical replication:** Publication/subscription model.
   Efficient and battle-tested, but replicates at the table level and requires
   careful configuration to exclude runtime tables. Each site would need a
   subscription configured at the hub.

2. **Application-level pull replication:** The LDAP server's replication puller
   queries the hub for changes and applies them locally. Full control over what
   data flows. More code to write, but the scope is narrow.

3. **Multi-master replication:** Sites can both read and write identity data.
   Rejected immediately — identity data is centrally mastered, and multi-master
   adds conflict resolution complexity with no benefit.

4. **Mesh replication:** Sites replicate to each other. Rejected — increases
   complexity dramatically for 184 nodes and violates the principle of a single
   authoritative source.

Key requirements:

- Only identity data replicates. Credentials, bind events, and audit data must
  NEVER cross site boundaries.
- Sites must survive WAN outages using cached identity data.
- The hub must support 184 sites pulling independently.
- Replication must be pull-based (sites initiate) to simplify hub firewall
  rules and avoid push-to-184-sites fan-out.

## Decision

Use **application-level pull replication** in a hub-and-spoke topology.

- The central hub maintains a change log with monotonic sequence numbers.
- Each site's replication puller connects to the hub via mTLS.
- The puller requests changes since its last acknowledged sequence number.
- Only `identity` schema data is included in change sets.
- Changes are applied in a local transaction.

The replication puller is a component of the LDAP server binary, running as an
async background task.

## Consequences

### Positive

- **Strict data scope control.** The application explicitly selects which
  tables and columns to replicate. There is no risk of accidentally replicating
  `runtime.credentials` through a misconfigured subscription.
- **Pull-based simplicity.** The hub does not need to track 184 outbound
  connections. Sites pull on their own schedule. The hub only needs to serve
  change set queries.
- **WAN-failure resilient.** When the WAN is down, the puller backs off and
  retries. The site continues operating on cached data.
- **Auditable replication.** Every change set has a sequence range and integrity
  digest. Gaps or corruption are detectable.
- **Site-scoped data.** The hub can filter change sets to only include data
  relevant to the requesting site, reducing bandwidth.

### Negative

- **Custom code.** Unlike PostgreSQL native replication, the puller and change
  log must be implemented and maintained. This is a deliberate trade-off for
  control over data scope.
- **Eventual consistency.** Sites may lag behind the hub. This is acceptable —
  password issuance is site-local and not affected by identity lag. The
  staleness detection mechanism (see replication-topology.md) provides
  visibility.
- **Hub is a single point of failure for replication.** If the hub is down,
  no site receives updates. Sites continue operating on cached data. A hub
  read replica can mitigate this.

### Neutral

- The change log at the hub must be periodically truncated (after all sites
  have acknowledged past a certain sequence). A background maintenance job
  handles this.
- Full reconciliation is needed periodically to detect drift that incremental
  replication might miss.
