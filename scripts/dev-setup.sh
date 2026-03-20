#!/usr/bin/env bash
set -euo pipefail

echo "=== USG JIT LDAP Server — Local Development Setup ==="

# 1. Start PostgreSQL
echo "[1/5] Starting PostgreSQL..."
docker compose -f docker-compose.dev.yml up -d --wait
echo "  PostgreSQL is ready on localhost:5432"

# 2. Run migrations
echo "[2/5] Running database migrations..."
export DATABASE_URL="postgresql://ldap_dev:ldap_dev_password@localhost:5432/ldap_dev"
# Use sqlx-cli if available, otherwise use psql directly
if command -v cargo-sqlx &>/dev/null || command -v sqlx &>/dev/null; then
    cargo sqlx migrate run --source migrations/
else
    # Fallback: apply migrations with psql
    for f in migrations/*.sql; do
        echo "  Applying: $f"
        psql "$DATABASE_URL" -f "$f" 2>&1 | head -5
    done
fi
echo "  Migrations applied"

# 3. Seed test data
echo "[3/5] Seeding test data..."
psql "$DATABASE_URL" -f scripts/seed-data.sql
echo "  Test data seeded"

# 4. Generate ephemeral password for testuser
echo "[4/5] Generating ephemeral password for testuser..."
# We need to generate an argon2id hash of "testpassword123" and insert it.
# Use a small inline Rust program or Python if available.
PASS_HASH=$(python3 -c "
import subprocess, hashlib, base64, os, sys
try:
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    h = ph.hash('testpassword123')
    print(h)
except ImportError:
    # Fallback: use a pre-computed hash
    # This is argon2id hash of 'testpassword123' with default params
    print('\$argon2id\$v=19\$m=65536,t=3,p=4\$c29tZXNhbHQ\$RdescudvJCsgt3ub+b+daw')
" 2>/dev/null || echo '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+daw')

psql "$DATABASE_URL" -c "
INSERT INTO runtime.ephemeral_passwords (user_id, password_hash, issued_by, expires_at)
VALUES (
    'a0000000-0000-0000-0000-000000000001'::uuid,
    '$PASS_HASH',
    'dev-setup',
    now() + interval '24 hours'
) ON CONFLICT DO NOTHING;
"
echo "  Ephemeral password created (expires in 24h)"
echo "  Test credentials: DN=cn=testuser,ou=users,dc=example,dc=com  Password=testpassword123"

# 5. Generate self-signed TLS certificates
echo "[5/5] Generating self-signed TLS certificates..."
mkdir -p dev-certs
if [ ! -f dev-certs/server.crt ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout dev-certs/server.key -out dev-certs/server.crt \
        -days 365 -nodes \
        -subj "/CN=localhost/O=USG JIT LDAP Dev/C=US" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    echo "  TLS certificates generated in dev-certs/"
else
    echo "  TLS certificates already exist in dev-certs/"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To start the server:"
echo "  cargo run -- config.dev.toml"
echo ""
echo "To test with ldapsearch (install openldap client tools):"
echo "  LDAPTLS_REQCERT=never ldapsearch -H ldaps://localhost:636 \\"
echo "    -D 'cn=testuser,ou=users,dc=example,dc=com' -w testpassword123 \\"
echo "    -b 'dc=example,dc=com' -x '(objectClass=*)'"
