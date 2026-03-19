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

# Run fuzz targets (requires nightly)
fuzz target='fuzz_decode_frame' runs='100000':
    cargo +nightly fuzz run {{target}} -- -max_len=65536 -runs={{runs}}
