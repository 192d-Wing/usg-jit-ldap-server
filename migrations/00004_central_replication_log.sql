-- Central hub replication log.
-- Records all identity changes for site replicas to consume.
-- This table exists ONLY on the central hub, not on site replicas.
--
-- NIST CP-9: Provides the change feed that enables site-local data backup
-- through replication.

CREATE TABLE IF NOT EXISTS replication_log (
    seq_number BIGSERIAL PRIMARY KEY,
    change_type VARCHAR(64) NOT NULL,
    entity_id UUID NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_replication_log_seq
    ON replication_log (seq_number);

CREATE INDEX IF NOT EXISTS idx_replication_log_entity
    ON replication_log (entity_id);

COMMENT ON TABLE replication_log IS
    'Central hub change log for identity replication. Queried by site pullers.';
