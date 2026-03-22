-- Add payload integrity hash and protocol version to replication_log.
--
-- NIST SI-7 (Information Integrity): SHA-256 digest of the canonical payload
-- enables sites to verify that replication data was not tampered with in transit.
--
-- Protocol version field enables safe schema evolution without breaking
-- existing site pullers.

ALTER TABLE replication_log
    ADD COLUMN IF NOT EXISTS payload_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS protocol_version INT NOT NULL DEFAULT 1;

-- Backfill: compute SHA-256 for existing rows.
-- payload_hash = SHA-256 of the JSONB payload cast to text (canonical form).
UPDATE replication_log
SET payload_hash = encode(sha256(payload::text::bytea), 'hex')
WHERE payload_hash IS NULL;

-- Now make it NOT NULL for future inserts.
ALTER TABLE replication_log
    ALTER COLUMN payload_hash SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_replication_log_protocol_version
    ON replication_log (protocol_version);

COMMENT ON COLUMN replication_log.payload_hash IS
    'SHA-256 hex digest of payload::text for integrity verification (NIST SI-7)';

COMMENT ON COLUMN replication_log.protocol_version IS
    'Replication protocol version. Sites reject entries with unknown versions.';
