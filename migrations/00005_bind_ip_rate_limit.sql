-- ============================================================
-- runtime.bind_ip_rate_limit_state
-- Per-source-IP rate limit counters for bind attempts.
--
-- NIST AC-7: Complements per-DN rate limiting by also enforcing
-- per-IP thresholds, preventing distributed brute-force attacks
-- that rotate target DNs from a single source.
-- ============================================================
CREATE TABLE IF NOT EXISTS runtime.bind_ip_rate_limit_state (
    source_ip     INET         PRIMARY KEY,
    attempt_count INT          NOT NULL DEFAULT 0,
    window_start  TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT ck_bind_ip_rate_limit_count_nonnegative CHECK (attempt_count >= 0)
);

CREATE INDEX idx_bind_ip_rate_limit_window
    ON runtime.bind_ip_rate_limit_state (window_start);

COMMENT ON TABLE runtime.bind_ip_rate_limit_state IS
    'Per-IP rate limit counters for bind attempts. '
    'NIST AC-7: prevents distributed brute-force from single source IP.';
