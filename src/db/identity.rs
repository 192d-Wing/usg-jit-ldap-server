//! Identity schema queries.
//!
//! CRUD operations against the identity tables: users, groups,
//! credentials, and entitlements.

/// Placeholder for identity record returned from the database.
pub struct IdentityRecord {
    pub dn: String,
    pub uid: String,
    pub display_name: Option<String>,
}

/// Look up an identity by distinguished name.
pub async fn find_by_dn(
    _pool: &sqlx::PgPool,
    _dn: &str,
) -> Result<Option<IdentityRecord>, sqlx::Error> {
    // TODO: query identity schema
    todo!("identity lookup")
}
