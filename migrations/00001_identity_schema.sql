-- Migration: 00001_identity_schema
-- Identity schema: replicated from central hub to all 184 sites
-- Contains ONLY user/group identity data — NO password material
--
-- NIST AC-6: least-privilege schema separation ensures replication roles
-- cannot access credential material stored in the runtime schema.
-- NIST SC-4: information flow enforcement between security domains.

CREATE SCHEMA IF NOT EXISTS identity;

-- ============================================================
-- identity.users
-- Authoritative user records, replicated from central hub.
-- ============================================================
CREATE TABLE identity.users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(64) NOT NULL,
    display_name  VARCHAR(256),
    email         VARCHAR(256),
    dn            VARCHAR(512) NOT NULL,
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT uq_users_dn       UNIQUE (dn),
    CONSTRAINT ck_users_username_nonempty CHECK (length(trim(username)) > 0),
    CONSTRAINT ck_users_dn_nonempty       CHECK (length(trim(dn)) > 0)
);

CREATE INDEX idx_users_username ON identity.users (username);
CREATE INDEX idx_users_dn       ON identity.users (dn);
CREATE INDEX idx_users_enabled  ON identity.users (enabled) WHERE enabled = TRUE;

-- ============================================================
-- identity.groups
-- Directory groups, replicated from central hub.
-- ============================================================
CREATE TABLE identity.groups (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    group_name  VARCHAR(128) NOT NULL,
    dn          VARCHAR(512) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_groups_group_name UNIQUE (group_name),
    CONSTRAINT uq_groups_dn         UNIQUE (dn),
    CONSTRAINT ck_groups_name_nonempty CHECK (length(trim(group_name)) > 0),
    CONSTRAINT ck_groups_dn_nonempty   CHECK (length(trim(dn)) > 0)
);

CREATE INDEX idx_groups_group_name ON identity.groups (group_name);
CREATE INDEX idx_groups_dn         ON identity.groups (dn);

-- ============================================================
-- identity.user_groups
-- Many-to-many membership relationship.
-- ============================================================
CREATE TABLE identity.user_groups (
    user_id  UUID NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES identity.groups (id) ON DELETE CASCADE,

    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX idx_user_groups_group_id ON identity.user_groups (group_id);

-- ============================================================
-- identity.sites
-- The 184 geographically distributed site definitions.
-- ============================================================
CREATE TABLE identity.sites (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    site_code  VARCHAR(16) NOT NULL,
    site_name  VARCHAR(256) NOT NULL,
    region     VARCHAR(64),
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_sites_site_code UNIQUE (site_code),
    CONSTRAINT ck_sites_code_nonempty CHECK (length(trim(site_code)) > 0)
);

CREATE INDEX idx_sites_site_code ON identity.sites (site_code);
CREATE INDEX idx_sites_region    ON identity.sites (region);

-- ============================================================
-- identity.user_site_policy
-- Per-user, per-site access authorization.
-- NIST AC-2: account management at the site granularity.
-- ============================================================
CREATE TABLE identity.user_site_policy (
    user_id        UUID    NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
    site_id        UUID    NOT NULL REFERENCES identity.sites (id) ON DELETE CASCADE,
    access_allowed BOOLEAN NOT NULL DEFAULT TRUE,

    PRIMARY KEY (user_id, site_id)
);

CREATE INDEX idx_user_site_policy_site_id ON identity.user_site_policy (site_id);

-- ============================================================
-- identity.replication_metadata
-- Tracks per-site replication state; one row per site.
-- ============================================================

-- Enum for replication sync status
CREATE TYPE identity.sync_status_enum AS ENUM ('synced', 'syncing', 'stale', 'error');

CREATE TABLE identity.replication_metadata (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id              UUID        NOT NULL REFERENCES identity.sites (id) ON DELETE CASCADE,
    last_sequence_number BIGINT      NOT NULL DEFAULT 0,
    last_sync_at         TIMESTAMPTZ,
    sync_status          identity.sync_status_enum NOT NULL DEFAULT 'stale',

    CONSTRAINT uq_replication_metadata_site_id UNIQUE (site_id),
    CONSTRAINT ck_replication_seq_nonnegative CHECK (last_sequence_number >= 0)
);
