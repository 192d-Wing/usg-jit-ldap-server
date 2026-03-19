# ADR-006: Rust with Minimal Dependencies

**Status:** Accepted

**Date:** 2026-03-19

## Context

The LDAP server is a security-critical service handling authentication
credentials in a government environment requiring ATO. The implementation
language affects:

1. **Memory safety** — The server handles untrusted network input (LDAP PDUs)
   and sensitive data (password hashes). Memory corruption vulnerabilities
   (buffer overflows, use-after-free, double-free) are the most common class
   of exploitable bugs in network services.

2. **Auditability** — ATO assessors must be able to review the codebase and
   its dependencies. A smaller dependency tree is easier to audit.

3. **Supply chain risk** — Each dependency is a potential vector for supply
   chain attacks. Government environments are increasingly scrutinizing
   third-party code.

4. **Performance** — The server must handle Bind and Search operations with
   low latency at 184 sites.

Languages considered:

- **C/C++**: Maximum control, but memory safety is the developer's
  responsibility. The history of LDAP server CVEs (OpenLDAP, 389-DS) is
  dominated by memory safety bugs.
- **Go**: Memory-safe with garbage collection, but GC pauses could affect
  latency. Larger binary size. Less precise control over memory layout
  (relevant for password zeroization).
- **Java**: Memory-safe, but JVM footprint is large for a lightweight service.
  Garbage collection makes deterministic memory zeroization difficult.
- **Rust**: Memory-safe without garbage collection. Zero-cost abstractions.
  Precise control over memory layout. Growing ecosystem of audited
  cryptographic libraries. No runtime.

## Decision

The server is implemented in **Rust** with a **minimal dependency footprint**.

### Dependency Principles

1. **Audit before adopt.** Every new dependency must be justified. Prefer
   standard library functionality where available.

2. **Prefer audited crates.** For cryptographic and security-sensitive
   functionality, use crates that have undergone third-party security audits
   (e.g., `rustls`, `ring`).

3. **Pin versions.** All dependencies are pinned to exact versions in
   `Cargo.lock`. Version updates require review.

4. **Minimize transitive dependencies.** A crate that pulls in 50 transitive
   dependencies is less preferable than one that pulls in 5, all else being
   equal.

5. **No `unsafe` in application code.** All `unsafe` usage is confined to
   vetted library crates. Application code uses only safe Rust.

### Expected Core Dependencies

| Crate | Purpose | Notes |
|---|---|---|
| `tokio` | Async runtime | Industry standard. Required for async I/O. |
| `rustls` | TLS implementation | Pure Rust. Audited. No OpenSSL dependency. |
| `tokio-rustls` | Tokio + rustls integration | Thin adapter layer. |
| `deadpool-postgres` or `bb8` | Connection pooling | Async PostgreSQL pool. |
| `tokio-postgres` | PostgreSQL client | Async PostgreSQL driver. |
| `argon2` | Password hashing | Audited implementation. |
| `zeroize` | Memory zeroization | Overwrites sensitive data on drop. |
| `serde` + `toml` | Configuration parsing | Deserialization of TOML config. |
| `tracing` | Structured logging | Async-aware structured logging. |

## Consequences

### Positive

- **Memory safety by default.** Rust's ownership system prevents buffer
  overflows, use-after-free, and data races at compile time. This eliminates
  the most common class of security vulnerabilities in network services.
- **Deterministic memory management.** No garbage collector. Password material
  can be reliably zeroized when the owning variable is dropped.
- **Small binary, small footprint.** The compiled binary is a single static
  executable with no runtime dependencies (beyond libc). Easy to deploy to
  184 sites.
- **Auditable dependency tree.** Minimal dependencies mean fewer crates for
  assessors to review. `cargo audit` checks for known vulnerabilities.
- **Performance.** Zero-cost abstractions and no GC pauses ensure consistent
  low-latency response times.

### Negative

- **Smaller talent pool.** Rust developers are less common than C, Java, or Go
  developers. Mitigated by the codebase being small and narrowly scoped.
- **Steeper learning curve.** The borrow checker requires familiarity.
  Mitigated by keeping the codebase simple and well-documented.
- **BER/ASN.1 codec must be implemented or sourced.** There is no dominant
  Rust LDAP codec library. May need to implement a minimal BER codec. This is
  acceptable given the narrow operation set (Bind, Search, Password Modify).

### Neutral

- Rust's async ecosystem (tokio) is mature and widely used in production
  network services.
- Cross-compilation for different site architectures (x86_64, aarch64) is
  straightforward with Rust's toolchain.
- The `rustls` TLS library avoids the OpenSSL dependency, which simplifies
  FIPS compliance discussion (though FIPS-validated rustls configurations may
  still require attention).
