# ADR-004: Ephemeral Passwords via JIT Broker, Never Replicated

**Status:** Accepted

**Date:** 2026-03-19

## Context

In a traditional LDAP deployment, user passwords are stored in the directory
and replicated along with other user attributes. This creates several problems:

1. **Password replication expands the blast radius.** A breach at any replica
   exposes all users' password hashes.
2. **Password lifecycle is tightly coupled to directory replication.** Password
   changes must propagate to all replicas before the user can authenticate
   at any site.
3. **Static passwords are high-value targets.** Long-lived passwords are
   susceptible to offline cracking if hashes are exfiltrated.

The operating environment uses a JIT (Just-In-Time) Broker that issues
time-limited credentials to users when they need access to a specific site.
This model is fundamentally different from traditional password management.

Key requirements:

- The JIT Broker decides when and where to issue credentials. The LDAP server
  does not participate in that decision.
- Issued passwords are site-specific. A password issued for Site A is stored
  only at Site A.
- Passwords have a TTL (time-to-live). Once expired, they are no longer valid
  for Bind.
- Password hashes must never appear in replication traffic.

## Decision

Ephemeral passwords are issued by the external JIT Broker and stored
exclusively in the site-local `runtime.credentials` table. The LDAP server:

- Verifies passwords during Bind by reading from `runtime.credentials`.
- Checks TTL expiry at verification time.
- Never generates, rotates, or replicates passwords.
- Zeroizes password material in memory after verification.

The `runtime` schema (containing credentials) is completely excluded from the
replication protocol. There is no configuration option to replicate it.

## Consequences

### Positive

- **Breach containment.** A compromise at one site exposes only the ephemeral
  passwords currently active at that site, not all users' long-term passwords.
- **No password replication.** Eliminates the risk of password hashes in
  transit across the WAN.
- **Short-lived credentials.** TTL enforcement means exfiltrated hashes become
  useless once the TTL expires.
- **Decoupled lifecycle.** Password issuance is independent of identity
  replication. A user can be added to a site's identity data via replication
  and receive a password from the Broker as a separate operation.
- **Clear separation of concerns.** The LDAP server verifies; the Broker
  issues. Neither does the other's job.

### Negative

- **Dependency on JIT Broker.** If the Broker is unavailable, no new passwords
  can be issued. Users with unexpired passwords can still authenticate, but new
  access requires the Broker.
- **User experience change.** Users do not set their own passwords via the LDAP
  server. The Password Modify extended operation, if enabled, is restricted to
  the Broker's service DN.
- **Credential gap on fresh sites.** A newly provisioned site has identity data
  (via replication) but no credentials until the Broker issues them. Users
  cannot authenticate until the Broker acts.

### Neutral

- The Broker's internal implementation (how it decides to issue, what policy it
  enforces) is out of scope for the LDAP server. The LDAP server trusts
  properly authenticated Broker requests.
- Password hash algorithm (Argon2id) and cost parameters are configured at the
  site level. The Broker hashes passwords before writing to the database.
