# Security Code Review Checklist

This checklist is for security-focused code reviews of the USG JIT LDAP Server.
Reviewers should verify each item during every pull request that touches
security-relevant code paths. Items marked [CRITICAL] are blocking; any failure
must be resolved before merge.

## 1. TLS Enforcement

- [ ] [CRITICAL] No `TcpStream` is used for LDAP processing without first passing
  through `TlsAcceptor`. Verify that all connection handling occurs after TLS
  handshake completion.
- [ ] [CRITICAL] Port 636 is the only listening port. No code opens port 389 or
  any other listener for LDAP traffic.
- [ ] [CRITICAL] The `build_tls_acceptor()` function fails with an error (not a
  warning) if certificate loading fails. The caller (main) must exit on error.
- [ ] Minimum TLS version is 1.3. The `build_server_config()` function does not
  accept "1.0", "1.1", or "1.2" as valid `min_version` values.
- [ ] Cipher suite selection uses rustls defaults (AEAD-only). No custom cipher
  suite configuration that could weaken the selection.
- [ ] [CRITICAL] Mutual TLS is mandatory. The `build_server_config()` function uses
  `WebPkiClientVerifier` with the configured CA certificate. Clients without valid
  certificates are rejected at the TLS handshake.
- [ ] Client certificate subject DN is extracted after handshake and included in
  the `ConnectionOpened` audit event and `LdapSession` for attribution.
- [ ] Certificate metadata is logged (chain position, size). Private key material
  is NEVER logged.

**Relevant files:** `src/tls.rs`, `src/main.rs`, `src/config.rs`

## 2. No Plaintext Code Paths

- [ ] [CRITICAL] `grep -rn "389" src/` does not reveal any port 389 listener or
  configuration option to enable plaintext LDAP.
- [ ] [CRITICAL] The StartTLS OID (`1.3.6.1.4.1.1466.20037`) does not appear in
  any code that would implement or recognize it.
- [ ] No `TcpStream` read/write operations occur before TLS negotiation in the
  connection handling path.
- [ ] The config validator rejects non-636 ports unless `allow_non_standard_port`
  is explicitly set (and this flag should never be true in production configs).
- [ ] No feature flag, environment variable, or configuration option can disable
  TLS requirement.

**Relevant files:** `src/tls.rs`, `src/main.rs`, `src/config.rs`, `src/ldap/password.rs`

## 3. Password Zeroization

- [ ] [CRITICAL] All `Vec<u8>` or `&[u8]` variables containing plaintext password
  bytes call `.zeroize()` before going out of scope or are wrapped in
  `Zeroizing<T>`.
- [ ] [CRITICAL] Password bytes from the Bind PDU are zeroized after
  `verify_password()` returns, regardless of success or failure.
- [ ] [CRITICAL] `hash_password()` zeroizes the plaintext input after hashing.
- [ ] No password bytes are copied to unprotected buffers (e.g., `String`,
  unprotected `Vec`, log messages).
- [ ] Intermediate hash computation buffers do not retain password-derived data
  after the function returns.
- [ ] The `zeroize` crate is in `Cargo.toml` dependencies (not just dev-dependencies).

**Relevant files:** `src/auth/password.rs`, `src/ldap/bind.rs`

## 4. Rate Limiting on All Auth Paths

- [ ] [CRITICAL] `RateLimiter::check_and_increment()` is called BEFORE
  `verify_password()` or any password hash retrieval in the Bind path.
- [ ] [CRITICAL] Rate limit check failure causes the Bind to be rejected
  immediately (no password verification occurs).
- [ ] Empty DN is rejected by the rate limiter (defense-in-depth).
- [ ] Rate limit state uses an atomic database upsert to prevent race conditions
  with concurrent Bind attempts.
- [ ] Rate limit thresholds are configurable but have secure defaults
  (max_bind_attempts > 0, window_secs > 0).
- [ ] A `RateLimitTriggered` audit event is emitted when the threshold is exceeded.

**Relevant files:** `src/auth/rate_limit.rs`, `src/auth/mod.rs`, `src/config.rs`

## 5. Audit Logging Completeness

- [ ] [CRITICAL] Every Bind attempt (success and all failure types) produces a
  `BindAttempt` audit event.
- [ ] [CRITICAL] Every Search request produces a `SearchRequest` event. Every
  Search completion produces a `SearchComplete` event.
- [ ] Every Password Modify operation produces a `PasswordModify` event.
- [ ] Rate limit triggers produce `RateLimitTriggered` events.
- [ ] TLS handshake failures produce `TlsError` events.
- [ ] Connection open/close produce `ConnectionOpened`/`ConnectionClosed` events.
- [ ] Service start/stop produce `ServiceStarted`/`ServiceStopped` events.
- [ ] Audit events are emitted BEFORE the LDAP response is sent to the client.
- [ ] Audit events never contain plaintext passwords, password hashes, or private
  key material.
- [ ] Audit failure (database write error) does not crash the service or block
  the LDAP operation.

**Relevant files:** `src/audit/events.rs`, `src/audit/mod.rs`, all operation handlers

## 6. SQL Injection Prevention

- [ ] [CRITICAL] All SQL queries use parameterized statements (`$1`, `$2`, etc.
  with `.bind()` calls). No string interpolation or concatenation of user input
  into SQL.
- [ ] `grep -rn "format!" src/db/` does not show any format string used to
  construct SQL queries.
- [ ] Search filter translation to SQL uses parameterized predicates, not string
  interpolation of filter values.
- [ ] DN values passed to database queries are always parameterized.
- [ ] No use of `sqlx::query()` with dynamically-constructed query strings.

**Relevant files:** `src/db/identity.rs`, `src/db/runtime.rs`, `src/auth/rate_limit.rs`

## 7. Input Validation on LDAP Messages

- [ ] [CRITICAL] BER/ASN.1 codec enforces a maximum PDU size. Messages exceeding
  the limit are rejected and the connection is closed.
- [ ] Bind requests with LDAP version != 3 are rejected.
- [ ] SASL Bind requests are rejected with `authMethodNotSupported`.
- [ ] Anonymous Binds (empty DN or empty password) are explicitly rejected.
- [ ] Search filter complexity is bounded (maximum depth, maximum components).
- [ ] LDAP strings reject embedded NULL bytes to prevent DN/filter comparison bypasses.
- [ ] BER length parsing uses `checked_shl()` to prevent integer overflow.
- [ ] Search `sizeLimit` is capped by server-side `max_result_size` regardless
  of the client's requested limit.
- [ ] Malformed BER encoding causes connection close, not a panic or undefined
  behavior.

**Relevant files:** `src/ldap/codec.rs`, `src/ldap/bind.rs`, `src/ldap/search.rs`

## 8. Error Handling

- [ ] [CRITICAL] Error messages returned to the client never contain: password
  bytes, password hashes, internal file paths, stack traces, database connection
  strings, or configuration details.
- [ ] [CRITICAL] "User not found", "account disabled", and "wrong password" produce
  the same client-visible error (`InvalidCredentials`) and the same audit failure
  reason (`invalid_credentials`) to prevent user enumeration.
- [ ] Password Modify returns `InsufficientAccessRights` (not `NoSuchObject`) for
  missing users to prevent user enumeration via extended operations.
- [ ] Account lockout also returns `InvalidCredentials` (same as wrong password)
  to prevent lockout status disclosure.
- [ ] Internal errors return a generic "internal server error" message. Detailed
  error information is logged server-side via tracing only — never in audit events.
- [ ] Database errors do not expose schema names, table names, or SQL to the client
  or to audit event records stored in the database.
- [ ] `unwrap()` calls are justified or replaced with proper error handling.
  `unwrap()` on user-controlled data is forbidden.

**Relevant files:** `src/ldap/bind.rs`, `src/ldap/search.rs`, `src/ldap/password.rs`

## 9. Dependency Audit

- [ ] `cargo audit` produces no known vulnerabilities in the dependency tree.
- [ ] The dependency set is minimal. New dependencies require justification for
  why existing dependencies or the standard library are insufficient.
- [ ] Critical dependencies are vetted:
  - `rustls` — pure Rust TLS, audited
  - `argon2` — RustCrypto implementation
  - `zeroize` — RustCrypto memory clearing
  - `sqlx` — compile-time checked SQL
  - `tokio` — async runtime (widely used, actively maintained)
  - `chrono` — time handling (well-known, stable)
  - `serde` / `serde_json` — serialization (ubiquitous, stable)
  - `tracing` — structured logging (Tokio project)
- [ ] No dependencies pull in `openssl-sys` or other C binding crates for
  cryptographic operations (unless explicitly justified).
- [ ] `Cargo.lock` is committed and reviewed for unexpected transitive dependency
  changes.

**Relevant files:** `Cargo.toml`, `Cargo.lock`

## 10. Memory Safety

- [ ] [CRITICAL] No `unsafe` blocks exist in the codebase unless explicitly
  justified with a safety comment explaining why the invariants hold.
- [ ] `grep -rn "unsafe" src/` returns zero results or only justified blocks.
- [ ] No raw pointer manipulation (`*const`, `*mut`) in application code.
- [ ] No use of `std::mem::transmute` or `std::mem::forget` (which could prevent
  zeroization).
- [ ] All array/slice indexing uses bounds-checked access or iterators.
- [ ] No integer overflow in size calculations (use `checked_add`, `checked_mul`,
  or `usize::MAX` guards where applicable).

**Relevant files:** All `src/**/*.rs`

## 11. Secret Handling

- [ ] [CRITICAL] `grep -rn "password" src/` — verify that no log statement,
  error message, or debug output includes password bytes or hashes.
- [ ] [CRITICAL] TLS private key content is never logged. Only the file path
  and a "loaded" confirmation are logged.
- [ ] Database connection strings are not logged in full (may contain credentials).
- [ ] The `Debug` impl for any struct containing secrets either omits the secret
  field or replaces it with `[REDACTED]`.
- [ ] Configuration deserialization does not log the raw TOML content (may contain
  database passwords).
- [ ] Audit events explicitly exclude password fields (verified by `AuditEvent`
  struct definitions).
- [ ] Environment variable values (especially `DATABASE_URL`) are not logged.

**Relevant files:** `src/config.rs`, `src/tls.rs`, `src/auth/password.rs`, `src/audit/events.rs`

## Review Signoff

| Item | Reviewer | Date | Pass/Fail | Notes |
|---|---|---|---|---|
| TLS Enforcement | | | | |
| No Plaintext Paths | | | | |
| Password Zeroization | | | | |
| Rate Limiting | | | | |
| Audit Completeness | | | | |
| SQL Injection | | | | |
| Input Validation | | | | |
| Error Handling | | | | |
| Dependency Audit | | | | |
| Memory Safety | | | | |
| Secret Handling | | | | |

**Reviewer:** ___________________________  **Date:** ___________

**Approved for merge:** [ ] Yes  [ ] No — issues noted above
