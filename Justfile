# USG JIT LDAP Server — development task runner
# Install just: https://github.com/casey/just

# Default: show available targets
default:
    @just --list

# Build the project in debug mode
build:
    cargo build

# Build for release
release:
    cargo build --release

# Run all tests
test:
    cargo test

# Run the server (debug mode)
run:
    cargo run

# Format all source code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt -- --check

# Run clippy lints
clippy:
    cargo clippy -- -D warnings

# Run database migrations (requires sqlx-cli)
migrate:
    sqlx migrate run

# Check that the project compiles without producing a binary
check:
    cargo check

# Remove build artifacts
clean:
    cargo clean

# Run all CI checks locally (fmt, clippy, test)
ci: fmt-check clippy test

# Run adversarial pen test scripts (requires running server)
pentest host='localhost' port='636':
    python3 tests/adversarial/tls_downgrade.py {{host}} {{port}}
    python3 tests/adversarial/malformed_ber.py {{host}} {{port}}
    python3 tests/adversarial/connection_flood.py {{host}} {{port}}
    python3 tests/adversarial/brute_force.py {{host}} {{port}}
