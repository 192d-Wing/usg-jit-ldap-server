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

# Security audit of dependencies
audit:
    cargo audit

# Check dependency licenses and advisories
deny:
    cargo deny check

# Run integration tests (requires PostgreSQL)
test-integration:
    docker compose -f docker-compose.test.yml up -d --wait
    DATABASE_URL="postgresql://ldap_test:ldap_test_password@localhost:5433/ldap_test" cargo test --test '*' -- --nocapture
    docker compose -f docker-compose.test.yml down

# Run all CI checks locally (fmt, clippy, test)
ci: fmt-check clippy test

# Full CI pipeline (local)
ci-full: fmt-check clippy test audit deny

# Run fuzz targets (requires nightly)
fuzz target='fuzz_decode_frame' runs='100000':
    cargo +nightly fuzz run {{target}} -- -max_len=65536 -runs={{runs}}

# Run adversarial pen test scripts (requires running server)
pentest host='localhost' port='636':
    python3 tests/adversarial/tls_downgrade.py {{host}} {{port}}
    python3 tests/adversarial/malformed_ber.py {{host}} {{port}}
    python3 tests/adversarial/connection_flood.py {{host}} {{port}}
    python3 tests/adversarial/brute_force.py {{host}} {{port}}

# Generate CycloneDX SBOM
sbom:
    cargo install cargo-cyclonedx 2>/dev/null || true
    cargo cyclonedx --format json
    @echo "SBOM generated: bom.json"
