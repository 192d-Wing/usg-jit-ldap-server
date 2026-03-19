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

# Run integration tests (requires PostgreSQL)
test-integration:
    docker compose -f docker-compose.test.yml up -d --wait
    DATABASE_URL="postgresql://ldap_test:ldap_test_password@localhost:5433/ldap_test" cargo test --test '*' -- --nocapture
    docker compose -f docker-compose.test.yml down

# Run all CI checks locally (fmt, clippy, test)
ci: fmt-check clippy test
