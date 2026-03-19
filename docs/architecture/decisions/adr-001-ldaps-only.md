# ADR-001: LDAPS-Only, No StartTLS or Cleartext LDAP

**Status:** Accepted

**Date:** 2026-03-19

## Context

LDAP clients can connect to directory servers via three transport modes:

1. **LDAP on port 389 (cleartext)** — No encryption. Credentials and directory
   data are transmitted in plaintext.
2. **LDAP on port 389 with StartTLS** — The client connects in cleartext and
   then upgrades to TLS via the StartTLS extended operation before sending
   credentials.
3. **LDAPS on port 636 (TLS-first)** — The connection is TLS-encrypted from
   the first byte. No cleartext phase.

This system operates in a government environment requiring ATO under NIST SP
800-53 Rev. 5. Password material is ephemeral and high-value. The system spans
184 sites with varying network infrastructure maturity.

Key considerations:

- **StartTLS stripping attacks:** An active network attacker can intercept the
  StartTLS negotiation and prevent the TLS upgrade, causing the client to send
  credentials in cleartext (or at least to a state where the server must decide
  whether to accept unauthenticated traffic).

- **Configuration complexity:** Supporting both port 389 (with StartTLS) and
  port 636 increases the number of configuration combinations, testing
  scenarios, and potential misconfiguration paths.

- **Client compatibility:** All clients in this environment (PAM modules, SSH,
  custom applications) support LDAPS. There is no requirement to support legacy
  clients that only speak plaintext LDAP.

- **Code complexity:** A StartTLS implementation requires an in-protocol state
  machine transition from cleartext to TLS, which is a source of subtle bugs
  in TLS upgrade handling.

## Decision

The server supports **LDAPS on port 636 only**. There is no listener on port
389. There is no StartTLS implementation. The StartTLS OID is not recognized
by the extended operation handler.

## Consequences

### Positive

- **Eliminates TLS stripping attacks.** There is no cleartext phase that an
  attacker can exploit.
- **Simplifies the codebase.** No StartTLS state machine. No dual-port
  configuration. No "did the client upgrade?" logic.
- **Reduces misconfiguration risk.** Operators cannot accidentally expose a
  plaintext LDAP port.
- **Clear security posture.** Assessors can verify "TLS is always on" without
  analyzing conditional upgrade paths.
- **Maps cleanly to NIST SC-8** (Transmission Confidentiality and Integrity).

### Negative

- **Clients must be configured for LDAPS.** Clients that default to port 389
  must be reconfigured. This is acceptable because the deployment environment
  controls all clients.
- **No fallback for misconfigured clients.** A client pointed at port 389 gets
  a connection refused, not a helpful error. This is intentional — failing
  closed is preferable to failing open.
- **Diverges from some LDAP conventions.** Some documentation and tooling
  assumes port 389. Operational documentation must clearly state port 636.

### Neutral

- Port 636 is an IANA-registered port for LDAPS. This is a standard,
  well-understood configuration.
