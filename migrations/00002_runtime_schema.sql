-- Migration: 00002_runtime_schema
-- Runtime schema: site-local ONLY — NEVER replicated
-- Contains ephemeral password state, bind events, audit data
--
-- NIST IA-5: credential storage is local-scope only.
-- NIST SC-4: runtime tables are excluded from all replication queries.
--
-- WARNING: Tables in this schema MUST NOT be included in any replication
-- configuration. The replication puller has no SELECT privilege on this
-- schema. Password hashes must never leave the site boundary.

CREATE SCHEMA IF NOT EXISTS runtime;

-- ============================================================
-- runtime.ephemeral_passwords
-- JIT-issued credentials with bounded TTL.
-- Passwords are issued by the external JIT Broker and consumed
-- during LDAP Bind operations. They are NEVER replicated.
--
-- NIST IA-5(6): authenticator storage is site-local only.
-- NIST SC-28: protection of information at rest — hash only,
-- never plaintext, never transmitted off-site.
-- ============================================================
CREATE TABLE runtime.ephemeral_passwords (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
    password_hash VARCHAR(256) NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    issued_by     VARCHAR(256) NOT NULL,
    used          BOOLEAN     NOT NULL DEFAULT FALSE,
    used_at       TIMESTAMPTZ,
    revoked       BOOLEAN     NOT NULL DEFAULT FALSE,

    CONSTRAINT ck_ephemeral_expires_after_issued CHECK (expires_at > issued_at),
    CONSTRAINT ck_ephemeral_hash_nonempty CHECK (length(password_hash) > 0),
    CONSTRAINT ck_ephemeral_used_at_consistency CHECK (
        (used = FALSE AND used_at IS NULL) OR (used = TRUE AND used_at IS NOT NULL)
    )
);

-- Primary lookup path: find valid (non-expired, non-revoked, non-used) password for a user
CREATE INDEX idx_ephemeral_passwords_user_expires
    ON runtime.ephemeral_passwords (user_id, expires_at)
    WHERE used = FALSE AND revoked = FALSE;

-- Cleanup path: find expired passwords for garbage collection
CREATE INDEX idx_ephemeral_passwords_expires
    ON runtime.ephemeral_passwords (expires_at)
    WHERE used = FALSE AND revoked = FALSE;

COMMENT ON TABLE runtime.ephemeral_passwords IS
    'Site-local ephemeral credentials. NEVER replicated. '
    'NIST IA-5: credential material does not leave the site boundary.';

-- ============================================================
-- runtime.bind_events
-- Immutable log of all LDAP Bind attempts.
-- Used for rate-limiting lookups and forensic analysis.
--
-- NIST AU-3: content of audit records (who, what, when, where, outcome).
-- NIST AC-7: unsuccessful logon attempts tracking.
-- ============================================================
CREATE TABLE runtime.bind_events (
    id             BIGSERIAL    PRIMARY KEY,
    user_dn        VARCHAR(512) NOT NULL,
    source_ip      INET         NOT NULL,
    success        BOOLEAN      NOT NULL,
    failure_reason VARCHAR(256),
    attempted_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_bind_events_user_dn_attempted
    ON runtime.bind_events (user_dn, attempted_at);

CREATE INDEX idx_bind_events_source_ip_attempted
    ON runtime.bind_events (source_ip, attempted_at);

COMMENT ON TABLE runtime.bind_events IS
    'Site-local bind attempt log. NEVER replicated. '
    'NIST AU-3: provides audit record content for authentication events.';

-- ============================================================
-- runtime.audit_queue
-- Durable queue for structured audit events pending forwarding
-- to a central SIEM or log aggregator.
--
-- NIST AU-6: audit review, analysis, and reporting.
-- NIST AU-9: protection of audit information.
-- ============================================================
CREATE TABLE runtime.audit_queue (
    id           BIGSERIAL    PRIMARY KEY,
    event_type   VARCHAR(128) NOT NULL,
    event_data   JSONB        NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    forwarded    BOOLEAN      NOT NULL DEFAULT FALSE,
    forwarded_at TIMESTAMPTZ
);

CREATE INDEX idx_audit_queue_forwarded_created
    ON runtime.audit_queue (forwarded, created_at)
    WHERE forwarded = FALSE;

COMMENT ON TABLE runtime.audit_queue IS
    'Site-local audit event queue. NEVER replicated. '
    'Events are forwarded to central SIEM asynchronously.';

-- ============================================================
-- runtime.rate_limit_state
-- Sliding window rate limit counters per user DN.
-- Checked BEFORE password hash computation to prevent CPU exhaustion.
--
-- NIST AC-7: unsuccessful logon attempts — enforces lockout thresholds.
-- ============================================================
CREATE TABLE runtime.rate_limit_state (
    user_dn       VARCHAR(512) PRIMARY KEY,
    attempt_count INT          NOT NULL DEFAULT 0,
    window_start  TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT ck_rate_limit_count_nonnegative CHECK (attempt_count >= 0)
);

CREATE INDEX idx_rate_limit_state_window
    ON runtime.rate_limit_state (window_start);

COMMENT ON TABLE runtime.rate_limit_state IS
    'Site-local rate limit counters. NEVER replicated. '
    'NIST AC-7: enforces bind attempt thresholds per DN.';

-- ============================================================
-- runtime.health_state
-- Key-value store for operational health signals.
-- Used by liveness/readiness probes and monitoring.
-- ============================================================
CREATE TABLE runtime.health_state (
    key        VARCHAR(128) PRIMARY KEY,
    value      JSONB        NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE runtime.health_state IS
    'Site-local health state. NEVER replicated. '
    'Operational telemetry for liveness and readiness probes.';
