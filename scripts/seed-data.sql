-- Seed data for local development and smoke testing.
-- Password hash is argon2id of "testpassword123"

-- Create schemas if they don't exist (migrations should handle this, but be safe)
-- INSERT test user
INSERT INTO identity.users (id, username, display_name, email, dn, enabled, created_at, updated_at)
VALUES (
    'a0000000-0000-0000-0000-000000000001'::uuid,
    'testuser',
    'Test User',
    'testuser@example.com',
    'cn=testuser,ou=users,dc=example,dc=com',
    true,
    now(),
    now()
) ON CONFLICT (dn) DO NOTHING;

-- INSERT test group
INSERT INTO identity.groups (id, group_name, dn, description, created_at, updated_at)
VALUES (
    'b0000000-0000-0000-0000-000000000001'::uuid,
    'testgroup',
    'cn=testgroup,ou=groups,dc=example,dc=com',
    'Test group for development',
    now(),
    now()
) ON CONFLICT (dn) DO NOTHING;

-- INSERT membership
INSERT INTO identity.memberships (user_id, group_id)
VALUES (
    'a0000000-0000-0000-0000-000000000001'::uuid,
    'b0000000-0000-0000-0000-000000000001'::uuid
) ON CONFLICT DO NOTHING;

-- INSERT broker user
INSERT INTO identity.users (id, username, display_name, email, dn, enabled, created_at, updated_at)
VALUES (
    'c0000000-0000-0000-0000-000000000001'::uuid,
    'jit-broker',
    'JIT Broker Service',
    'broker@example.com',
    'cn=jit-broker,ou=services,dc=example,dc=com',
    true,
    now(),
    now()
) ON CONFLICT (dn) DO NOTHING;

-- Note: Ephemeral password must be inserted by the dev-setup script
-- because it needs a fresh argon2id hash generated at setup time.
