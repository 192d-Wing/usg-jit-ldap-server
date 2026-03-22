# NIST SP 800-53 Rev. 5 — Control-to-Code Traceability Matrix

This document maps every NIST SP 800-53 Rev. 5 control claim in the USG JIT
LDAP Server source code to its exact file and line location. It is generated
from a comprehensive search of all `NIST` comments in the `src/` directory.

Assessors can verify each claim by opening the referenced file at the specified
line number. Each row also identifies the verification mechanism (test, config,
or operational procedure) that validates the control implementation.

---

## AC — Access Control

| Control | Title | File | Line(s) | Implementation | Verification |
|---------|-------|------|---------|----------------|--------------|
| AC-2 | Account Management | `src/db/identity.rs` | 219 | Per-site account authorization via `identity.user_site_policy` table; accounts managed centrally, replicated to sites | Integration test: `test_full_bind_lifecycle`, `test_bind_with_disabled_user` |
| AC-3 | Access Enforcement | `src/ldap/session.rs` | 141, 171 | Session state machine rejects all operations before Bind; exhaustive match on session state prevents bypass | Unit test: `test_search_before_bind_rejected` (session.rs:417, mod.rs:327) |
| AC-3 | Access Enforcement | `src/ldap/search.rs` | 126, 135 | Defense-in-depth bound-session check in search handler | Unit test: `test_search_requires_bound_session` |
| AC-3 | Access Enforcement | `src/ldap/password.rs` | 165, 220, 247, 267 | Broker authorization boundary; bound-session and broker-DN checks before password modify | Unit tests: `test_non_broker_rejected`, `test_unbound_session_rejected` |
| AC-3 | Access Enforcement | `src/ldap/mod.rs` | 110 | Top-level dispatcher rejects all ops before authentication | Unit test: `test_search_before_bind_rejected` |
| AC-4 | Information Flow Enforcement | `src/replication/puller.rs` | 75 | Replication puller enforces one-way identity-only data flow from hub to site | Design: dual-schema separation (`identity` vs `runtime`) |
| AC-6 | Least Privilege | `src/db/identity.rs` | 6-7 | Identity module has no access to runtime schema; cannot read credentials | Code review: module boundaries, DB role permissions |
| AC-6 | Least Privilege | `src/ldap/search.rs` | 63, 184 | Backend performs attribute-level filtering; only identity attributes returned | Unit test: `test_entries_converted_to_result_entries` |
| AC-6 | Least Privilege | `src/auth/mod.rs` | 397, 446 | Search scoped to identity schema only; breadth limited per bound identity | Unit tests: `test_scope_base_object_exact_match`, `test_scope_single_level_immediate_children` |
| AC-7 | Unsuccessful Logon Attempts | `src/auth/rate_limit.rs` | 10-16, 46, 77, 129 | Per-DN sliding window rate limiter; checked BEFORE password hash lookup to prevent CPU exhaustion | Config: `max_bind_attempts`, `rate_limit_window_secs`; unit test: `test_rate_limit_error_display` |
| AC-7 | Unsuccessful Logon Attempts | `src/ldap/bind.rs` | 40, 99, 179, 194 | Bind handler records failed attempts and enforces lockout threshold | Unit tests: `test_failed_auth`, `test_successful_bind` |
| AC-7 | Unsuccessful Logon Attempts | `src/db/runtime.rs` | 218 | Database-level rate limit check must happen before hash retrieval | Integration test: `test_concurrent_bind_same_password` |
| AC-7 | Unsuccessful Logon Attempts | `src/config.rs` | 182-183 | Rate limit configuration with secure defaults | Unit test: `test_defaults_applied` |

## AU — Audit and Accountability

| Control | Title | File | Line(s) | Implementation | Verification |
|---------|-------|------|---------|----------------|--------------|
| AU-2 | Audit Events | `src/config.rs` | 225-226 | Audit events selection configuration; all security-relevant events are logged | Unit test: `test_parse_minimal_config` |
| AU-3 | Content of Audit Records | `src/audit/events.rs` | 8-15, 21 | Structured audit event carrying all NIST AU-3 required context: who, what, when, where, outcome | Unit tests: `test_bind_attempt_serialization`, `test_event_type_names`, `test_password_modify_event`, `test_rate_limit_event` |
| AU-3 | Content of Audit Records | `src/config.rs` | 226 | Audit content includes timestamps, source IPs, DNs, and outcomes | Config validation tests |
| AU-3 | Content of Audit Records | `src/db/runtime.rs` | 186 | Database audit records capture who (user_dn), what, when, where | Integration tests |
| AU-3 | Content of Audit Records | `src/main.rs` | 546 | Structured logging ensures audit records contain required fields | Code review |
| AU-5 | Response to Audit Processing Failures | `src/audit/mod.rs` | 87 | In fail_closed mode, callers MUST handle error by rejecting the operation | Unit tests: `test_default_failure_policy_is_fail_open`, `test_failure_count_starts_at_zero` |
| AU-5 | Response to Audit Processing Failures | `src/config.rs` | 239, 250 | Configurable fail-open/fail-closed audit failure policy | Unit test: `test_defaults_applied` |
| AU-5 | Response to Audit Processing Failures | `src/auth/mod.rs` | 264, 322 | Bind rejected in fail-closed mode when audit persistence fails | Code review |
| AU-6 | Audit Review and Analysis | `src/db/runtime.rs` | 260 | Events durably queued in local `runtime.audit_queue` for SIEM forwarding | Operational: audit forwarding runbook |
| AU-8 | Time Stamps | `src/audit/events.rs` | 15 | UTC timestamps; NTP synchronization is operational dependency | Unit test: `test_bind_attempt_serialization` |
| AU-12 | Audit Record Generation | `src/audit/mod.rs` | 9 | Audit events generated at point of operation, before response sent | Unit tests: `test_tracing_only_logger_does_not_panic`, `test_tracing_only_log_checked_succeeds`, `test_sync_logging_does_not_panic` |

## CM — Configuration Management

| Control | Title | File | Line(s) | Implementation | Verification |
|---------|-------|------|---------|----------------|--------------|
| CM-6 | Configuration Settings | `src/config.rs` | 9, 46, 351, 375 | All settings loaded from validated TOML; secure defaults; startup validation fails closed | Unit tests: `test_parse_minimal_config`, `test_non_standard_port_rejected_without_flag`, `test_empty_database_url_rejected`, `test_defaults_applied` |
| CM-6 | Configuration Settings | `src/db/pool.rs` | 6, 31 | Pool sizing and connection parameters externalized as configuration | Config validation |
| CM-6 | Configuration Settings | `src/main.rs` | 8, 58 | Configuration loaded and validated before any service starts | Startup sequence verification |
| CM-6 | Configuration Settings | `src/audit/events.rs` | 86 | Configuration management events captured in audit log | Unit test: `test_event_type_names` |

## CP — Contingency Planning

| Control | Title | File | Line(s) | Implementation | Verification |
|---------|-------|------|---------|----------------|--------------|
| CP-9 | System Backup | `src/replication/health.rs` | 119 | Replication health monitoring detects sync failures for contingency awareness | Unit tests: `test_record_success_resets_failures`, `test_record_failure_increments_counter`, `test_health_report_marks_stale` |
| CP-9 | System Backup | `src/replication/mod.rs` | 175 | Hub-to-site replication provides local survivability; sites operate independently | Unit tests: `test_default_config_is_disabled`, `test_valid_enabled_config` |
| CP-10 | System Recovery | `src/replication/puller.rs` | 746 | Recovery procedures for replication gap detection and re-sync | Unit test: `test_backoff_calculation`; operational: replication recovery runbook |

## IA — Identification and Authentication

| Control | Title | File | Line(s) | Implementation | Verification |
|---------|-------|------|---------|----------------|--------------|
| IA-2 | Identification and Authentication | `src/ldap/bind.rs` | 58, 95, 141, 163 | Simple Bind with DN identification; anonymous binds rejected (empty DN or password) | Unit tests: `test_anonymous_bind_rejected`, `test_empty_password_rejected`, `test_successful_bind` |
| IA-2 | Identification and Authentication | `src/auth/mod.rs` | 48, 122 | Primary authentication enforcement point; dummy hash on unknown DN prevents timing oracle | Integration test: `test_full_bind_lifecycle` |
| IA-2 | Identification and Authentication | `src/ldap/session.rs` | 249, 295 | Session-level identification check; anonymous access explicitly prohibited | Unit tests: `test_anonymous_bind_rejected`, `test_session_bind_rejects_without_handler` |
| IA-2 | Identification and Authentication | `src/main.rs` | 379 | Connection-level authenticator setup | Code review |
| IA-5 | Authenticator Management | `src/auth/password.rs` | 47, 63, 77, 98 | Password material never retained longer than necessary; zeroized after hash/verify | Unit tests: `test_hash_and_verify_success`, `test_verify_wrong_password`, `test_hash_produces_phc_format` |
| IA-5 | Authenticator Management | `src/ldap/bind.rs` | 58, 158 | Password bytes passed by reference, not retained | Unit test: `test_successful_bind` |
| IA-5 | Authenticator Management | `src/db/runtime.rs` | 7, 29 | Password storage scope: all credential material in runtime schema only | Integration test: `test_password_ttl_enforcement` |
| IA-5 | Authenticator Management | `src/auth/mod.rs` | 168, 234, 274 | One-time password enforcement via transactional lock; zeroized after verification | Integration tests |
| IA-5 | Authenticator Management | `src/config.rs` | 183 | Password TTL and ephemeral credential management configuration | Unit test: `test_defaults_applied` |
| IA-5(1) | Password-Based Authentication | `src/ldap/password.rs` | 148 | Passwords hashed with Argon2id; PHC string format | Unit test: `test_successful_password_modify` |
| IA-5(1) | Password-Based Authentication | `src/auth/mod.rs` | 688, 727 | Password store uses Argon2id hashing; plaintext zeroized inside `hash_password()` | Unit test: `test_hash_produces_phc_format` |
| IA-5(6) | Authenticator Feedback | `src/db/runtime.rs` | 29 | `password_hash` field is Argon2id; no plaintext feedback | Code review |

## SC — System and Communications Protection

| Control | Title | File | Line(s) | Implementation | Verification |
|---------|-------|------|---------|----------------|--------------|
| SC-4 | Information in Shared Resources | `src/db/mod.rs` | 3 | Prevents information leakage between security domains via schema separation | Code review: dual-schema architecture |
| SC-5 | Denial of Service Protection | `src/main.rs` | 272 | Connection limit enforcement; maximum concurrent connections | Config: `max_connections` |
| SC-8 | Transmission Confidentiality | `src/tls.rs` | 8-10, 69 | All connections TLS-wrapped; no plaintext code path exists | Integration tests: `test_tls_acceptor_builds_with_valid_certs`, `test_tls_acceptor_fails_without_cert_file`; pen test: `tls_downgrade.py` |
| SC-8 | Transmission Confidentiality | `src/main.rs` | 122-123, 135 | Server refuses to start without valid TLS certificates | Startup validation |
| SC-8 | Transmission Confidentiality | `src/replication/mod.rs` | 47, 115, 129 | Replication connection validated for TLS; insecure rejected | Unit test: `test_rejects_insecure_connection` |
| SC-8 | Transmission Confidentiality | `src/replication/puller.rs` | 277, 357 | Replication uses TLS enforced by sslmode in connection string | Code review |
| SC-8 | Transmission Confidentiality | `src/config.rs` | 375 | Standard port 636 prevents accidental cleartext exposure | Unit test: `test_non_standard_port_rejected_without_flag` |
| SC-12 | Cryptographic Key Establishment | `src/tls.rs` | 102 | Private key details not logged; key material protected | Code review |
| SC-13 | Cryptographic Protection | `src/tls.rs` | 106, 183, 191 | Only strong ciphersuites and TLS 1.3 permitted; strongest available selected | Unit test: `test_unsupported_tls_version`; integration: `test_tls_12_rejected`, `test_tls_10_rejected` |
| SC-17 | PKI Certificates | `src/tls.rs` | 70, 94, 207 | Certificates validated at startup; metadata logged for operational awareness | Unit tests: `test_missing_cert_file_returns_error`, `test_missing_key_file_returns_error` |
| SC-23 | Session Authenticity | `src/main.rs` | 263, 362 | One LDAP session per TLS connection; no session tokens or cookies | Unit test: `test_new_session_is_connected`, `test_unbind_closes_session` |

## SI — System and Information Integrity

| Control | Title | File | Line(s) | Implementation | Verification |
|---------|-------|------|---------|----------------|--------------|
| SI-4 | System Monitoring | `src/admin.rs` | 6 | Runtime health information for operational awareness | Operational: monitoring runbook |
| SI-4 | System Monitoring | `src/config.rs` | 59, 277 | Monitoring configuration for system health endpoints | Config validation |
| SI-4 | System Monitoring | `src/main.rs` | 188 | System monitoring for operational awareness at startup | Startup sequence |
| SI-7 | Information Integrity | `src/replication/puller.rs` | 395, 549 | Replication payload integrity verification via SHA-256 digests and sequence numbers | Unit test: `test_backoff_calculation`; design: monotonic sequence detection |
| SI-10 | Information Input Validation | `src/ldap/codec.rs` | 130, 1184 | Maximum message size enforcement; oversized messages rejected to prevent memory exhaustion | Unit test: `test_message_size_limit_enforced`, `test_filter_depth_limit_enforced`; property tests: `prop_decode_never_panics_on_random_input`, `prop_decode_filter_never_panics` |
| SI-10 | Information Input Validation | `src/auth/rate_limit.rs` | 160 | Per-IP search rate limiting prevents enumeration attacks | Config: search rate limit parameters |
| SI-10 | Information Input Validation | `src/auth/mod.rs` | 423, 485, 523, 621 | Input validation on base_dn; LIKE wildcard escaping prevents SQL injection | Unit tests: `test_escape_like_wildcards_percent`, `test_escape_like_wildcards_underscore`, `test_escape_like_wildcards_backslash`, `test_escape_like_wildcards_all_special` |
| SI-10 | Information Input Validation | `src/main.rs` | 427 | Accumulated buffer size check rejects oversized messages | Code review |

---

## Summary

| Family | Controls Implemented | Primary Modules |
|--------|---------------------|-----------------|
| AC (Access Control) | AC-2, AC-3, AC-4, AC-6, AC-7 | `src/ldap/session.rs`, `src/auth/rate_limit.rs`, `src/ldap/password.rs` |
| AU (Audit and Accountability) | AU-2, AU-3, AU-5, AU-6, AU-8, AU-12 | `src/audit/events.rs`, `src/audit/mod.rs`, `src/config.rs` |
| CM (Configuration Management) | CM-6 | `src/config.rs`, `src/db/pool.rs` |
| CP (Contingency Planning) | CP-9, CP-10 | `src/replication/health.rs`, `src/replication/puller.rs` |
| IA (Identification and Authentication) | IA-2, IA-5, IA-5(1), IA-5(6) | `src/ldap/bind.rs`, `src/auth/password.rs`, `src/db/runtime.rs` |
| SC (System and Communications Protection) | SC-4, SC-5, SC-8, SC-12, SC-13, SC-17, SC-23 | `src/tls.rs`, `src/main.rs`, `src/replication/mod.rs` |
| SI (System and Information Integrity) | SI-4, SI-7, SI-10 | `src/ldap/codec.rs`, `src/auth/mod.rs`, `src/replication/puller.rs` |

**Total NIST comment markers in source code:** 95+
**Total control families covered:** 7
**Total distinct controls referenced:** 25+
