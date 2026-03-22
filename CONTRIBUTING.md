# Contributing to USG JIT LDAP Server

## Prerequisites

- **Rust 1.75+** — install via [rustup](https://rustup.rs/)
- **PostgreSQL 15+** — running locally or in a container
- **TLS certificates** — self-signed certs are fine for local development (see below)

## Local Development Setup

1. **Clone the repository and check out your branch:**

   ```bash
   git clone <repo-url>
   cd usg-jit-ldap-server
   git checkout -b feat/your-feature
   ```

2. **Copy configuration templates:**

   ```bash
   cp config.example.toml config.toml
   cp .env.example .env
   ```

3. **Set up the database:**

   ```bash
   createdb ldap_server
   # Run migrations (requires sqlx-cli):
   cargo install sqlx-cli --no-default-features --features postgres
   sqlx migrate run
   ```

4. **Generate self-signed TLS certificates for local dev:**

   ```bash
   mkdir -p certs
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
     -out certs/server.crt -days 365 -nodes \
     -subj "/CN=localhost"
   ```

   Update `config.toml` to point at these paths.

5. **Build and run:**

   ```bash
   cargo build
   cargo run
   ```

## Branch Naming Conventions

- `feat/` — new features or capabilities
- `fix/` — bug fixes
- `docs/` — documentation changes only

## Code Style

- Run `cargo fmt` before committing. All code must be formatted with rustfmt.
- Run `cargo clippy` and fix any warnings. CI will fail on clippy warnings.
- Keep dependencies minimal and auditable. Do not add new crates without discussion.

## Testing

```bash
# Run all tests
cargo test

# Run tests with logging output
RUST_LOG=debug cargo test -- --nocapture
```

Write tests for all new functionality. Place unit tests in the same file as the code
they test (in a `#[cfg(test)] mod tests` block). Place integration tests in `tests/`.

## Security

- **Never commit secrets** — no private keys, passwords, tokens, or `.env` files.
- All passwords must be hashed with argon2 before storage.
- All network communication must use TLS; plaintext LDAP is not supported.
- Report security issues privately; do not open public issues for vulnerabilities.
