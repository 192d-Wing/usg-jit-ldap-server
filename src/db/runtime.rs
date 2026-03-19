//! Runtime schema queries.
//!
//! Manages JIT-provisioned accounts, temporary credentials,
//! and session metadata in the runtime schema.

/// A runtime-provisioned account record.
pub struct RuntimeAccount {
    pub dn: String,
    pub provisioned_at: i64,
    pub expires_at: i64,
}

/// Look up an active runtime account.
pub async fn find_active_account(
    _pool: &sqlx::PgPool,
    _dn: &str,
) -> Result<Option<RuntimeAccount>, sqlx::Error> {
    // TODO: query runtime schema for non-expired accounts
    todo!("runtime account lookup")
}
