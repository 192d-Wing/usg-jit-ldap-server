-- Per-user mTLS enforcement flag.
--
-- NIST IA-3: Allows high-privilege accounts (brokers, admins) to require
-- client certificate authentication at the TLS layer, while regular users
-- can authenticate with password-only LDAP Bind.
--
-- Replicated from central hub as part of the identity schema.

ALTER TABLE identity.users
    ADD COLUMN IF NOT EXISTS require_client_cert BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN identity.users.require_client_cert IS
    'When TRUE, the user must present a valid TLS client certificate during '
    'the connection handshake. Bind attempts without a client cert are rejected.';
