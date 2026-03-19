# Project Charter: USG JIT LDAP Server

## Purpose

Build a minimal, security-focused LDAP server in Rust for a JIT password broker environment. The server provides LDAPS-only identity lookups and authentication at 184 geographically distributed sites, with centrally-managed identity data and site-local ephemeral password state.

## Non-Goals

This project explicitly does NOT aim to:

- Replace OpenLDAP or 389 Directory Server for general use
- Support the full LDAPv3 specification
- Implement directory modification operations (add/delete/modify)
- Support SASL, StartTLS, or cleartext LDAP
- Implement LDAP-native replication protocols
- Provide a plugin or extension framework

## Success Criteria

1. LDAPS service on port 636 that handles Bind and Search against PostgreSQL
2. JIT Broker can issue ephemeral passwords via Password Modify ExtOp or direct DB API
3. Identity data replicates from central to 184 sites; password state does not
4. Each site operates independently during WAN outages using local data
5. Code comments map to NIST SP 800-53 Rev. 5 controls for ATO support
6. Minimal dependency footprint, auditable codebase

## Stakeholders

- Security / ATO assessors
- Site operations teams
- JIT Broker service owner
- Identity management team

## Timeline

- Phase 1: Architecture, schema, protocol design
- Phase 2: Core LDAPS listener, Bind, Search
- Phase 3: Replication, Password Modify, audit logging
- Phase 4: Hardening, compliance review, operational tooling
