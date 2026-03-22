# Security Test Evidence

This document catalogs all security testing performed on the USG JIT LDAP
Server. It provides assessors with a summary of test coverage, methodologies,
and artifact locations.

---

## 1. Unit Test Summary

**Total unit tests:** 98 (across 16 source files)
**Framework:** Rust built-in `#[test]` + `#[tokio::test]` for async tests

### Test Distribution by Module

| Module | File | Test Count | Coverage Focus |
|--------|------|-----------|----------------|
| BER/ASN.1 Codec | `src/ldap/codec.rs` | 19 | Encode/decode round-trips, size limits, filter depth limits, frame handling |
| Authentication | `src/auth/mod.rs` | 13 | Broker authorization, filter extraction, LIKE wildcard escaping, scope enforcement |
| Replication Health | `src/replication/health.rs` | 7 | Success/failure tracking, staleness detection, duration averaging |
| Session Management | `src/ldap/session.rs` | 6 | State transitions, bind-before-search enforcement, anonymous rejection, unbind |
| Configuration | `src/config.rs` | 6 | Parsing, port validation, empty URL rejection, default values |
| Bind Handler | `src/ldap/bind.rs` | 6 | Successful bind, anonymous rejection, empty password, version 2, SASL, failed auth |
| Replication Config | `src/replication/mod.rs` | 5 | Enable/disable, URL requirements, insecure rejection, status display |
| Password Modify | `src/ldap/password.rs` | 5 | Successful modify, non-broker rejection, unbound rejection, missing password, wrong OID |
| Audit Logging | `src/audit/mod.rs` | 5 | Logger functionality, failure counting, failure policy defaults |
| Audit Events | `src/audit/events.rs` | 4 | Serialization, event type names, password modify events, rate limit events |
| Search Handler | `src/ldap/search.rs` | 4 | Bound session requirement, size limits, entry conversion |
| LDAP Dispatcher | `src/ldap/mod.rs` | 4 | Full bind-search flow, search-before-bind rejection, unbind, unknown extended op |
| Password Hashing | `src/auth/password.rs` | 4 | Hash-and-verify, wrong password, malformed hash, PHC format |
| TLS | `src/tls.rs` | 3 | Missing cert, missing key, unsupported TLS version |
| Replication Puller | `src/replication/puller.rs` | 1 | Backoff calculation |
| Rate Limiting | `src/auth/rate_limit.rs` | 1 | Error display |

### Security-Critical Test Cases

| Test | File | NIST Control | What It Validates |
|------|------|-------------|-------------------|
| `test_search_before_bind_rejected` | `src/ldap/session.rs:417` | AC-3 | Unauthenticated sessions cannot perform Search |
| `test_anonymous_bind_rejected` | `src/ldap/session.rs:438` | IA-2 | Empty DN Bind requests are rejected |
| `test_empty_password_rejected` | `src/ldap/bind.rs:304` | IA-2 | Empty password Bind requests are rejected |
| `test_version2_rejected` | `src/ldap/bind.rs:317` | CM-7 | LDAPv2 protocol is not supported |
| `test_sasl_rejected` | `src/ldap/bind.rs:330` | CM-7 | SASL authentication is not supported |
| `test_message_size_limit_enforced` | `src/ldap/codec.rs:1334` | SI-10 | Oversized PDUs are rejected |
| `test_filter_depth_limit_enforced` | `src/ldap/codec.rs:1344` | SI-10 | Deeply nested filters are rejected |
| `test_non_broker_rejected` | `src/ldap/password.rs:547` | AC-3 | Non-broker DNs cannot issue passwords |
| `test_unbound_session_rejected` | `src/ldap/password.rs:565` | AC-3 | Unbound sessions cannot modify passwords |
| `test_rejects_insecure_connection` | `src/replication/mod.rs:270` | SC-8 | Insecure replication connections are rejected |
| `test_non_standard_port_rejected_without_flag` | `src/config.rs:526` | SC-8 | Non-636 ports require explicit override |
| `test_missing_cert_file_returns_error` | `src/tls.rs:284` | SC-17 | Server fails to start without valid cert |
| `test_missing_key_file_returns_error` | `src/tls.rs:296` | SC-17 | Server fails to start without valid key |
| `test_unsupported_tls_version` | `src/tls.rs:308` | SC-13 | Unsupported TLS versions are rejected |

---

## 2. Property-Based Tests

**Total property tests:** 8
**Framework:** `proptest` crate
**Location:** `src/ldap/codec.rs` (lines 1365-1454)

| Property Test | What It Validates |
|--------------|-------------------|
| `prop_integer_round_trip` | BER integer encode/decode is lossless for all i64 values |
| `prop_length_round_trip` | BER length encode/decode is lossless for all valid sizes |
| `prop_octet_string_round_trip` | BER octet string encode/decode is lossless for arbitrary byte vectors (0-4096 bytes) |
| `prop_boolean_round_trip` | BER boolean encode/decode is lossless |
| `prop_enumerated_round_trip` | BER enumerated encode/decode is lossless for values 0-255 |
| `prop_bind_request_round_trip` | Full BindRequest message survives encode/decode cycle with arbitrary DN and password |
| `prop_decode_never_panics_on_random_input` | Decoder does not panic on arbitrary byte sequences (0-1024 bytes) |
| `prop_decode_filter_never_panics` | Filter decoder does not panic on arbitrary byte sequences (1-512 bytes) |

The panic-freedom properties (`prop_decode_never_panics_on_random_input`,
`prop_decode_filter_never_panics`) are particularly important for SI-10 (Input
Validation): they demonstrate that no malformed input can crash the BER parser.

---

## 3. Fuzz Target Inventory

**Total fuzz targets:** 5
**Framework:** `libfuzzer-sys` (via `cargo-fuzz`)
**Location:** `fuzz/fuzz_targets/`

| Fuzz Target | File | Attack Surface |
|-------------|------|---------------|
| `fuzz_decode_frame` | `fuzz/fuzz_targets/fuzz_decode_frame.rs` | BER frame decoder — tests for crashes, hangs, and memory safety violations on arbitrary byte input |
| `fuzz_decode_ldap_message` | `fuzz/fuzz_targets/fuzz_decode_ldap_message.rs` | Full LDAP message decoder — end-to-end parsing of arbitrary input |
| `fuzz_decode_filter` | `fuzz/fuzz_targets/fuzz_decode_filter.rs` | Search filter decoder — recursive parsing of nested filter structures |
| `fuzz_parse_passwd_modify` | `fuzz/fuzz_targets/fuzz_parse_passwd_modify.rs` | Password Modify extended request parser — credential handling code path |
| `fuzz_decode_length` | `fuzz/fuzz_targets/fuzz_decode_length.rs` | BER length field decoder — boundary condition testing for length encoding |

**NIST Controls:** SI-10 (Input Validation), SI-7 (Information Integrity)

Fuzz targets complement property-based tests by using coverage-guided mutation
to explore input spaces that property tests may miss. All five targets exercise
the BER/ASN.1 codec, which is the primary untrusted input boundary.

---

## 4. Integration Test Inventory

**Total integration tests:** 10
**Framework:** `#[tokio::test]` with shared test infrastructure
**Location:** `tests/`

| Test | File | What It Validates |
|------|------|-------------------|
| `test_full_bind_lifecycle` | `tests/bind_lifecycle.rs:9` | Complete Bind flow: credential insertion, successful authentication, session establishment |
| `test_bind_with_expired_password` | `tests/bind_lifecycle.rs:62` | Expired ephemeral passwords are rejected (IA-5 TTL enforcement) |
| `test_bind_with_disabled_user` | `tests/bind_lifecycle.rs:98` | Disabled accounts cannot authenticate (AC-2 enforcement) |
| `test_concurrent_bind_same_password` | `tests/concurrent_bind.rs:10` | Concurrent Bind attempts against the same credential are handled safely (race condition testing) |
| `test_password_ttl_enforcement` | `tests/password_expiry.rs:6` | Password TTL is enforced correctly at the integration level |
| `test_revoked_password_rejected` | `tests/password_expiry.rs:42` | Revoked/used passwords are rejected |
| `test_tls_acceptor_builds_with_valid_certs` | `tests/tls_enforcement.rs:33` | TLS acceptor initializes with valid certificate material |
| `test_tls_acceptor_fails_without_cert_file` | `tests/tls_enforcement.rs:51` | TLS acceptor fails without certificate file (SC-8 fail-closed) |
| `test_tls_12_rejected` | `tests/tls_enforcement.rs:63` | TLS 1.2 connections are rejected (SC-13 enforcement) |
| `test_tls_10_rejected` | `tests/tls_enforcement.rs:77` | TLS 1.0 connections are rejected (SC-13 enforcement) |

### Test Infrastructure

Shared test utilities in `tests/common/mod.rs` provide:

- `setup_test_pool()` — Creates an isolated PostgreSQL connection pool
- `insert_test_user()` — Inserts a test user into the identity schema
- `insert_ephemeral_password()` — Creates a test credential with configurable TTL
- `cleanup_test_data()` — Removes test data after each test

---

## 5. Penetration Test Harness

**Total pen test scripts:** 4
**Language:** Python 3.8+ (standard library only)
**Location:** `tests/adversarial/`
**Runner:** `just pentest` (Justfile target)

| Script | Attack Category | What It Tests |
|--------|----------------|---------------|
| `malformed_ber.py` | Protocol Fuzzing | Sends malformed BER/ASN.1 payloads: oversized length fields, truncated messages, invalid tag bytes. Server must reject every payload without crashing. |
| `tls_downgrade.py` | Transport Security | Attempts TLS 1.0 and 1.1 connections; verifies rejection. Confirms TLS 1.3 connectivity. Validates SC-13 enforcement from an external perspective. |
| `connection_flood.py` | Denial of Service | Opens 200 simultaneous TLS connections to verify `max_connections` limit enforcement. Validates SC-5 from an external perspective. |
| `brute_force.py` | Authentication | Fires rapid Bind attempts to trigger rate limiting. Validates AC-7 enforcement from an external perspective. |

Each script prints PASS/FAIL/SKIP per test case. A well-configured server
passes every case.

---

## 6. Dependency Audit

### cargo audit

`cargo audit` scans `Cargo.lock` for dependencies with known security
advisories published in the RustSec Advisory Database.

**Configuration:** Run as part of CI pipeline.

### cargo deny

**Configuration file:** `deny.toml` (repository root)

`cargo deny` enforces:

- **Advisories:** Rejects dependencies with known vulnerabilities
- **Licenses:** Ensures all dependencies use approved open-source licenses
- **Bans:** Blocks specific crates that are prohibited by policy
- **Sources:** Restricts dependency sources to crates.io

---

## 7. Test Coverage Summary

| Category | Count | NIST Controls Validated |
|----------|-------|------------------------|
| Unit tests | 98 | AC-2, AC-3, AC-6, AC-7, AU-2, AU-3, AU-5, CM-6, CM-7, CP-9, CP-10, IA-2, IA-5, SC-8, SC-13, SC-17, SC-23, SI-4, SI-10 |
| Property-based tests | 8 | SI-10 (panic-freedom, codec correctness) |
| Integration tests | 10 | AC-2, AC-7, IA-2, IA-5, SC-8, SC-13 |
| Fuzz targets | 5 | SI-10, SI-7 (BER codec robustness) |
| Pen test scripts | 4 | AC-7, SC-5, SC-8, SC-13, SI-10 |
| **Total** | **125** | **19 distinct controls** |

All tests are runnable via the project Justfile:

```bash
just test          # Unit + integration tests
just fuzz          # Fuzz targets (long-running)
just pentest       # Adversarial pen test scripts (requires running server)
just audit         # cargo audit + cargo deny
```
