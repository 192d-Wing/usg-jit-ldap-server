# ADR-005: Minimal LDAPv3 Operation Set

**Status:** Accepted

**Date:** 2026-03-19

## Context

The full LDAPv3 specification (RFC 4511 and related RFCs) defines a broad set
of operations:

| Operation | RFC 4511 Section |
|---|---|
| Bind | 4.2 |
| Unbind | 4.3 |
| Search | 4.5 |
| Modify | 4.6 |
| Add | 4.7 |
| Delete | 4.8 |
| ModifyDN | 4.9 |
| Compare | 4.10 |
| Abandon | 4.11 |
| Extended Operations | 4.12 |

General-purpose directory servers implement all of these. However, this is not
a general-purpose directory server. Its role is narrowly defined:

1. **Authenticate users** (Bind) against ephemeral passwords.
2. **Look up identity data** (Search) for client applications.
3. **Optionally accept password issuance** (Password Modify ExtOp) from the
   JIT Broker.

Identity data is managed centrally and replicated to sites. The LDAP server
never modifies identity data. There is no use case for LDAP Add, Delete,
Modify, or ModDN operations.

## Decision

The server implements only the following LDAPv3 operations:

| Operation | Status | Purpose |
|---|---|---|
| **Bind** (Simple) | Implemented | User authentication |
| **Unbind** | Implemented | Connection teardown |
| **Search** | Implemented | Identity data lookup |
| **Password Modify ExtOp** | Optional | JIT Broker password issuance |

All other operations receive `resultCode: unwillingToPerform` (53).

Specific rejections:

- **SASL Bind**: Not implemented. Simple Bind over TLS is sufficient. SASL adds
  significant code complexity (mechanism negotiation, multi-step authentication)
  with no benefit in this environment.
- **StartTLS ExtOp**: Not recognized. See ADR-001.
- **Anonymous Bind**: Explicitly rejected. See security invariants.
- **Modify/Add/Delete/ModDN**: Not implemented. Identity data is read-only at
  sites.
- **Compare**: Not implemented. Clients can achieve the same result with Search.
- **Abandon**: Not implemented in v1. May be added if long-running searches
  become a concern.

## Consequences

### Positive

- **Dramatically reduced code surface.** Fewer operations means fewer code
  paths to audit, test, and secure.
- **Reduced attack surface.** Each unimplemented operation is one less potential
  vulnerability. Modify and Add operations in particular are historically
  rich sources of authorization bypass bugs in LDAP servers.
- **Simpler authorization model.** No need for ACLs governing who can modify
  which attributes. All data access is read-only (Search) or authentication
  (Bind).
- **Clear scope for assessors.** ATO reviewers can verify the complete
  operation set exhaustively. There is no hidden functionality.

### Negative

- **Not a drop-in replacement.** Applications that expect LDAP write operations
  cannot use this server. This is intentional — identity writes go through the
  central management system, not LDAP.
- **No Compare operation.** Some clients use Compare for password checking.
  These clients must use Bind instead. In practice, Bind is the standard
  authentication mechanism.
- **No Abandon.** Long-running Search operations cannot be cancelled by the
  client. Mitigated by query timeouts and result size limits.

### Neutral

- The `unwillingToPerform` response for unsupported operations is a standard
  LDAPv3 behavior. Well-behaved clients handle it gracefully.
- If future requirements emerge (e.g., Compare for specific use cases), the
  operation set can be expanded. The architecture does not preclude additions;
  it simply starts minimal.
