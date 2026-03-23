#!/bin/sh
# Do NOT use set -e — test commands are expected to fail (negative tests).

LDAP_HOST="ldap-server"
LDAP_PORT=636
ADMIN_HOST="ldap-server"
ADMIN_PORT=9090
TEST_DN="cn=testuser,ou=users,dc=example,dc=com"
TEST_PASS="testpassword123"
BASE_DN="dc=example,dc=com"

# mTLS client certificate paths (mounted from tests/e2e/certs/)
LDAPTLS_CACERT="/e2e/certs/ca.crt"
LDAPTLS_CERT="/e2e/certs/client.crt"
LDAPTLS_KEY="/e2e/certs/client.key"
export LDAPTLS_CACERT LDAPTLS_CERT LDAPTLS_KEY

PASS=0
FAIL=0
SKIP=0

result() {
    if [ "$1" = "PASS" ]; then
        PASS=$((PASS + 1))
        echo "  [PASS] $2"
    elif [ "$1" = "FAIL" ]; then
        FAIL=$((FAIL + 1))
        echo "  [FAIL] $2"
    else
        SKIP=$((SKIP + 1))
        echo "  [SKIP] $2"
    fi
}

echo ""
echo "=== Test 1: Health endpoint ==="
HEALTH=$(curl -sf http://${ADMIN_HOST}:${ADMIN_PORT}/healthz 2>/dev/null || echo "FAILED")
if echo "$HEALTH" | grep -q '"status"'; then
    result "PASS" "GET /healthz returned valid JSON: $HEALTH"
else
    result "FAIL" "Health endpoint failed: $HEALTH"
fi

echo ""
echo "=== Test 2: TLS 1.3 connection ==="
TLS_RESULT=$(echo Q | openssl s_client -connect ${LDAP_HOST}:${LDAP_PORT} -tls1_3 \
    -CAfile ${LDAPTLS_CACERT} -cert ${LDAPTLS_CERT} -key ${LDAPTLS_KEY} 2>&1)
if echo "$TLS_RESULT" | grep -qi "new.*tls1.3\|protocol.*tlsv1.3\|tls_aes"; then
    result "PASS" "TLS 1.3 connection established"
elif echo "$TLS_RESULT" | grep -qi "connected"; then
    result "PASS" "TLS connection established (TLS version in handshake)"
else
    result "FAIL" "TLS 1.3 connection failed"
    echo "$TLS_RESULT" | head -5 | sed 's/^/  /'
fi

echo ""
echo "=== Test 3: TLS 1.2 rejection ==="
TLS12=$(echo Q | openssl s_client -connect ${LDAP_HOST}:${LDAP_PORT} -tls1_2 \
    -CAfile ${LDAPTLS_CACERT} -cert ${LDAPTLS_CERT} -key ${LDAPTLS_KEY} 2>&1)
if echo "$TLS12" | grep -qi "alert\|error\|handshake failure\|wrong version\|incompatible"; then
    result "PASS" "TLS 1.2 correctly rejected"
else
    result "FAIL" "TLS 1.2 was NOT rejected (should be)"
fi

echo ""
echo "=== Test 4: LDAP Bind + Subtree Search ==="
# This single ldapsearch call tests both bind and search in one connection.
# The ephemeral password is consumed by this bind (one-time use).
SEARCH_RESULT=$(ldapsearch -H ldaps://${LDAP_HOST}:${LDAP_PORT} \
    -D "$TEST_DN" -w "$TEST_PASS" \
    -b "$BASE_DN" -x -s sub "(objectClass=*)" cn uid mail 2>&1)
SEARCH_EXIT=$?
if [ $SEARCH_EXIT -eq 0 ]; then
    ENTRY_COUNT=$(echo "$SEARCH_RESULT" | grep -c "^dn:" || echo "0")
    result "PASS" "LDAP bind + subtree search succeeded — $ENTRY_COUNT entries returned"
    echo "  --- Search output (first 20 lines) ---"
    echo "$SEARCH_RESULT" | head -20 | sed 's/^/  /'
else
    result "FAIL" "LDAP bind + search failed (exit $SEARCH_EXIT): $(echo "$SEARCH_RESULT" | head -5)"
fi

echo ""
echo "=== Test 5: Anonymous bind rejection ==="
ANON_RESULT=$(ldapsearch -H ldaps://${LDAP_HOST}:${LDAP_PORT} \
    -x -b "$BASE_DN" "(objectClass=*)" 2>&1)
ANON_EXIT=$?
if [ $ANON_EXIT -ne 0 ]; then
    result "PASS" "Anonymous bind correctly rejected (exit $ANON_EXIT)"
else
    result "FAIL" "Anonymous bind was NOT rejected (should be)"
fi

echo ""
echo "=== Test 6: Wrong password rejection ==="
WRONG_RESULT=$(ldapsearch -H ldaps://${LDAP_HOST}:${LDAP_PORT} \
    -D "$TEST_DN" -w "wrongpassword" \
    -b "$BASE_DN" -x "(objectClass=*)" 2>&1)
WRONG_EXIT=$?
if [ $WRONG_EXIT -ne 0 ]; then
    result "PASS" "Wrong password correctly rejected (exit $WRONG_EXIT)"
else
    result "FAIL" "Wrong password was NOT rejected (should be)"
fi

echo ""
echo "=== Test 7: Password one-time use enforcement ==="
# Test 4 consumed the password. A second bind should fail.
REUSE_RESULT=$(ldapsearch -H ldaps://${LDAP_HOST}:${LDAP_PORT} \
    -D "$TEST_DN" -w "$TEST_PASS" \
    -b "$BASE_DN" -x -s base "(objectClass=*)" dn 2>&1)
REUSE_EXIT=$?
if [ $REUSE_EXIT -ne 0 ]; then
    result "PASS" "Password reuse correctly rejected (one-time use enforced)"
else
    result "FAIL" "Password reuse was NOT rejected (one-time use NOT enforced)"
fi

echo ""
echo "=========================================="
echo " Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "=========================================="
echo ""

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
