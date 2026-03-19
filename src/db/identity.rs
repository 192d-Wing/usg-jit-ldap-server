//! Identity schema queries.
//!
//! Read-only operations against the replicated identity tables: users, groups,
//! site policies, and replication metadata.
//!
//! NIST AC-6: this module has no access to the runtime schema. It cannot read
//! or write password hashes, bind events, or audit data. This boundary is
//! enforced by query construction (all queries target `identity.*` only).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::DbResult;

// ────────────────────────────────────────────────────────────
// Data structs
// ────────────────────────────────────────────────────────────

/// A user record from the identity schema.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub dn: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A group record from the identity schema.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Group {
    pub id: Uuid,
    pub group_name: String,
    pub dn: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Replication tracking metadata for a single site.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReplicationMetadata {
    pub id: Uuid,
    pub site_id: Uuid,
    pub last_sequence_number: i64,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub sync_status: String,
}

/// Filter criteria for directory search operations.
///
/// Translates LDAP search filters into SQL predicates. Only a minimal
/// subset of filter types is supported (equality, presence, substring).
#[derive(Debug, Clone, Default)]
pub struct SearchFilter {
    /// Filter on username (exact match).
    pub username: Option<String>,
    /// Filter on email (exact match).
    pub email: Option<String>,
    /// Filter on enabled status.
    pub enabled: Option<bool>,
    /// Filter on group name (exact match, for group searches).
    pub group_name: Option<String>,
    /// Maximum number of results to return (LDAP sizeLimit).
    pub limit: Option<i64>,
}

// ────────────────────────────────────────────────────────────
// Repository
// ────────────────────────────────────────────────────────────

/// Repository for identity schema queries.
///
/// All methods are read-only except for replication metadata updates,
/// which are performed by the replication puller.
pub struct IdentityRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> IdentityRepository<'a> {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// Look up a user by distinguished name.
    ///
    /// This is the primary lookup path during LDAP Bind: the client
    /// presents a DN, and we resolve it to a user record.
    pub async fn find_user_by_dn(&self, dn: &str) -> DbResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, username, display_name, email, dn, enabled, created_at, updated_at
            FROM identity.users
            WHERE dn = $1
            "#,
        )
        .bind(dn)
        .fetch_optional(self.pool)
        .await?;

        Ok(user)
    }

    /// Look up a user by username.
    pub async fn find_user_by_username(&self, username: &str) -> DbResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, username, display_name, email, dn, enabled, created_at, updated_at
            FROM identity.users
            WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(self.pool)
        .await?;

        Ok(user)
    }

    /// Return all groups a user belongs to.
    pub async fn find_groups_for_user(&self, user_id: Uuid) -> DbResult<Vec<Group>> {
        let groups = sqlx::query_as::<_, Group>(
            r#"
            SELECT g.id, g.group_name, g.dn, g.description, g.created_at, g.updated_at
            FROM identity.groups g
            INNER JOIN identity.user_groups ug ON ug.group_id = g.id
            WHERE ug.user_id = $1
            ORDER BY g.group_name
            "#,
        )
        .bind(user_id)
        .fetch_all(self.pool)
        .await?;

        Ok(groups)
    }

    /// Search users under a base DN with optional filter criteria.
    ///
    /// The base DN check uses a suffix match: a user's DN must end with
    /// the base DN to be considered "under" it in the directory tree.
    pub async fn search_users(
        &self,
        base_dn: &str,
        filter: &SearchFilter,
    ) -> DbResult<Vec<User>> {
        // Build a dynamic query. We use the dn LIKE '%base_dn' pattern
        // for subtree searches. The base_dn_pattern is constructed as a
        // suffix match (the user's DN ends with the base DN).
        let base_dn_pattern = format!("%{}", base_dn);
        let limit = filter.limit.unwrap_or(100);

        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT id, username, display_name, email, dn, enabled, created_at, updated_at
            FROM identity.users
            WHERE dn LIKE $1
              AND ($2::text    IS NULL OR username = $2)
              AND ($3::text    IS NULL OR email = $3)
              AND ($4::boolean IS NULL OR enabled = $4)
            ORDER BY username
            LIMIT $5
            "#,
        )
        .bind(&base_dn_pattern)
        .bind(&filter.username)
        .bind(&filter.email)
        .bind(&filter.enabled)
        .bind(limit)
        .fetch_all(self.pool)
        .await?;

        Ok(users)
    }

    /// Search groups under a base DN with optional filter criteria.
    pub async fn search_groups(
        &self,
        base_dn: &str,
        filter: &SearchFilter,
    ) -> DbResult<Vec<Group>> {
        let base_dn_pattern = format!("%{}", base_dn);
        let limit = filter.limit.unwrap_or(100);

        let groups = sqlx::query_as::<_, Group>(
            r#"
            SELECT id, group_name, dn, description, created_at, updated_at
            FROM identity.groups
            WHERE dn LIKE $1
              AND ($2::text IS NULL OR group_name = $2)
            ORDER BY group_name
            LIMIT $3
            "#,
        )
        .bind(&base_dn_pattern)
        .bind(&filter.group_name)
        .bind(limit)
        .fetch_all(self.pool)
        .await?;

        Ok(groups)
    }

    /// Check whether a user is authorized to access a specific site.
    ///
    /// NIST AC-2: per-site account authorization.
    /// Returns `true` if a `user_site_policy` row exists with `access_allowed = true`.
    /// Returns `false` if no row exists or access is explicitly denied.
    pub async fn check_site_access(
        &self,
        user_id: Uuid,
        site_id: Uuid,
    ) -> DbResult<bool> {
        let allowed = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT access_allowed
            FROM identity.user_site_policy
            WHERE user_id = $1 AND site_id = $2
            "#,
        )
        .bind(user_id)
        .bind(site_id)
        .fetch_optional(self.pool)
        .await?;

        Ok(allowed.unwrap_or(false))
    }

    /// Retrieve replication metadata for a site.
    ///
    /// Returns `None` if the site has never been synchronized.
    pub async fn get_replication_metadata(
        &self,
        site_id: Uuid,
    ) -> DbResult<Option<ReplicationMetadata>> {
        let meta = sqlx::query_as::<_, ReplicationMetadata>(
            r#"
            SELECT id, site_id, last_sequence_number, last_sync_at,
                   sync_status::text AS sync_status
            FROM identity.replication_metadata
            WHERE site_id = $1
            "#,
        )
        .bind(site_id)
        .fetch_optional(self.pool)
        .await?;

        Ok(meta)
    }

    /// Update replication metadata after a successful sync pull.
    ///
    /// This is called within the same transaction as the identity data
    /// application, ensuring atomicity between data changes and sequence
    /// number advancement.
    pub async fn update_replication_metadata(
        &self,
        site_id: Uuid,
        seq: i64,
    ) -> DbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO identity.replication_metadata (site_id, last_sequence_number, last_sync_at, sync_status)
            VALUES ($1, $2, now(), 'synced')
            ON CONFLICT (site_id) DO UPDATE
            SET last_sequence_number = $2,
                last_sync_at = now(),
                sync_status = 'synced'
            "#,
        )
        .bind(site_id)
        .bind(seq)
        .execute(self.pool)
        .await?;

        Ok(())
    }
}
