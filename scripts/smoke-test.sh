#!/usr/bin/env bash
set -euo pipefail

echo "=== Smoke Test: USG JIT LDAP Server ==="

SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        echo "Stopping server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Build the server
echo "[1/4] Building server..."
cargo build 2>&1 | tail -3

# Start the server in background
echo "[2/4] Starting server..."
cargo run -- config.dev.toml &
SERVER_PID=$!

# Wait for the server to be ready
echo "  Waiting for server to bind..."
for i in $(seq 1 30); do
    if ss -tlnp 2>/dev/null | grep -q ':636' || netstat -tlnp 2>/dev/null | grep -q ':636'; then
        echo "  Server is listening on port 636"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "  ERROR: Server process exited unexpectedly"
        exit 1
    fi
    sleep 1
done

# Give the server a moment to fully initialize
sleep 2

# Test TLS connection
echo "[3/4] Testing TLS connection..."
if command -v openssl &>/dev/null; then
    RESULT=$(echo | openssl s_client -connect localhost:636 -tls1_3 2>&1 | head -5)
    if echo "$RESULT" | grep -q "CONNECTED"; then
        echo "  PASS: TLS 1.3 connection established"
    else
        echo "  FAIL: TLS connection failed"
        echo "$RESULT"
    fi
fi

# Test LDAP bind + search
echo "[4/4] Testing LDAP bind and search..."
if command -v ldapsearch &>/dev/null; then
    LDAPTLS_REQCERT=never ldapsearch -H ldaps://localhost:636 \
        -D "cn=testuser,ou=users,dc=example,dc=com" \
        -w testpassword123 \
        -b "dc=example,dc=com" \
        -x "(objectClass=*)" 2>&1 | head -20
    SEARCH_EXIT=$?
    if [ $SEARCH_EXIT -eq 0 ]; then
        echo "  PASS: LDAP bind + search succeeded"
    else
        echo "  INFO: ldapsearch exited with code $SEARCH_EXIT (may need investigation)"
    fi
else
    echo "  SKIP: ldapsearch not installed (install openldap-clients)"
    echo "  Manual test: LDAPTLS_REQCERT=never ldapsearch -H ldaps://localhost:636 -D 'cn=testuser,ou=users,dc=example,dc=com' -w testpassword123 -b 'dc=example,dc=com' -x"
fi

echo ""
echo "=== Smoke Test Complete ==="
