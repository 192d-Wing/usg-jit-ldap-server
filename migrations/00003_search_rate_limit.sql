-- Search rate limiting: per-source-IP sliding window.
-- Site-local only — NEVER replicated.
-- NIST SI-10: Input validation — limits search abuse.
CREATE TABLE IF NOT EXISTS runtime.search_rate_limit_state (
    source_ip    INET PRIMARY KEY,
    search_count INT NOT NULL DEFAULT 0 CHECK (search_count >= 0),
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE runtime.search_rate_limit_state IS
    'Per-IP search rate limiting. Site-local only — NEVER replicated.';
