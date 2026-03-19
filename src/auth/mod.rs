// SPDX-License-Identifier: TBD
//
// Authentication Module
//
// Provides the DatabaseAuthenticator that implements the Authenticator trait
// from the protocol layer. Wires together identity lookup, rate limiting,
// ephemeral password verification, and audit event emission.
//
// NIST SP 800-53 Rev. 5:
// - IA-2 (Identification and Authentication): Users must present a valid DN
//   and ephemeral password. The authenticator resolves the DN to a user record,
//   checks rate limits, verifies the password hash, and records the outcome.
// - IA-5 (Authenticator Management): Ephemeral passwords are verified against
//   argon2id hashes. Plaintext password material is zeroized after verification.
// - AC-7 (Unsuccessful Logon Attempts): Rate limiting is checked BEFORE
//   password hash computation to prevent CPU exhaustion.

pub mod password;
pub mod rate_limit;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use sqlx::PgPool;

use crate::audit::events::{AuditEvent, BindOutcome};
use crate::audit::AuditLogger;
use crate::ldap::bind::{AuthResult, Authenticator};

use rate_limit::RateLimiter;

// ---------------------------------------------------------------------------
// DatabaseAuthenticator
// ---------------------------------------------------------------------------

/// Production authenticator backed by PostgreSQL.
///
/// Implements the Authenticator trait from the protocol layer, wiring together:
/// 1. Identity lookup (identity.users by DN)
/// 2. Rate limit check (runtime.rate_limit_state)
/// 3. Ephemeral password retrieval (runtime.ephemeral_passwords)
/// 4. Password verification (argon2id)
/// 5. Bind event recording (runtime.bind_events)
/// 6. Audit event emission (runtime.audit_queue + tracing)
///
/// NIST IA-2: This is the primary identification and authentication enforcement point.
pub struct DatabaseAuthenticator {
    pool: Arc<PgPool>,
    rate_limiter: RateLimiter,
    audit: AuditLogger,
    /// Socket address of the current connection, used for audit logging.
    /// Set per-connection when constructing the authenticator.
    peer_addr: SocketAddr,
}

impl DatabaseAuthenticator {
    /// Create a new authenticator for a specific client connection.
    ///
    /// Each connection gets its own authenticator instance carrying the
    /// peer address for audit attribution.
    pub fn new(
        pool: Arc<PgPool>,
        rate_limiter: RateLimiter,
        audit: AuditLogger,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            pool,
            rate_limiter,
            audit,
            peer_addr,
        }
    }
}

impl Authenticator for DatabaseAuthenticator {
    /// Verify the given DN and password against the database.
    ///
    /// Authentication flow:
    /// 1. Check rate limit (AC-7) — reject if exceeded, BEFORE hash computation.
    /// 2. Look up user by DN in identity.users — reject if not found or disabled.
    /// 3. Find valid ephemeral password in runtime.ephemeral_passwords.
    /// 4. Verify plaintext against stored argon2id hash (IA-5).
    /// 5. Mark password as used on success.
    /// 6. Record bind event and emit audit event.
    /// 7. Zeroize password material.
    fn authenticate<'a>(
        &'a self,
        dn: &'a str,
        password_bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = AuthResult> + Send + 'a>> {
        Box::pin(async move {
            // Step 1: Rate limit check (NIST AC-7).
            // This MUST happen before any password hash computation to prevent
            // CPU exhaustion via repeated argon2 evaluations.
            if let Err(_e) = self.rate_limiter.check_and_increment(dn).await {
                let event = AuditEvent::bind_attempt(
                    self.peer_addr,
                    dn,
                    BindOutcome::RateLimited,
                );
                self.audit.log(event).await;
                return AuthResult::AccountLocked;
            }

            // Step 2: Look up user by DN in identity schema.
            let user = match sqlx::query_as::<_, UserRow>(
                r#"
                SELECT id, username, dn, enabled
                FROM identity.users
                WHERE dn = $1
                "#,
            )
            .bind(dn)
            .fetch_optional(self.pool.as_ref())
            .await
            {
                Ok(Some(u)) => u,
                Ok(None) => {
                    // NIST IA-2: Perform dummy hash verification to prevent
                    // timing-based user enumeration. Without this, an attacker
                    // can distinguish "user exists" from "user not found" by
                    // measuring response time.
                    let _ = password::verify_password(
                        password_bytes.to_vec(),
                        "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    );
                    tracing::warn!(dn = %dn, peer = %self.peer_addr, "bind: user not found");
                    self.record_failure(dn, "user_not_found").await;
                    let event = AuditEvent::bind_attempt(
                        self.peer_addr,
                        dn,
                        BindOutcome::InvalidCredentials,
                    );
                    self.audit.log(event).await;
                    return AuthResult::InvalidCredentials;
                }
                Err(e) => {
                    tracing::error!(dn = %dn, error = %e, "bind: identity lookup failed");
                    let event = AuditEvent::bind_attempt(
                        self.peer_addr,
                        dn,
                        BindOutcome::InternalError {
                            detail: e.to_string(),
                        },
                    );
                    self.audit.log(event).await;
                    return AuthResult::InternalError(e.to_string());
                }
            };

            // Check user is enabled.
            if !user.enabled {
                tracing::warn!(dn = %dn, "bind: account disabled");
                self.record_failure(dn, "account_disabled").await;
                let event = AuditEvent::bind_attempt(
                    self.peer_addr,
                    dn,
                    BindOutcome::InvalidCredentials,
                );
                self.audit.log(event).await;
                return AuthResult::InvalidCredentials;
            }

            // Step 3 + 4 + 5: Atomic password fetch, verify, and mark-as-used.
            // NIST IA-5: One-time password enforcement via transactional lock.
            // Uses SELECT FOR UPDATE SKIP LOCKED to prevent concurrent use of
            // the same ephemeral password (race condition fix).
            let mut tx = match self.pool.begin().await {
                Ok(tx) => tx,
                Err(e) => {
                    tracing::error!(dn = %dn, error = %e, "bind: failed to begin transaction");
                    let event = AuditEvent::bind_attempt(
                        self.peer_addr,
                        dn,
                        BindOutcome::InternalError {
                            detail: "transaction error".into(),
                        },
                    );
                    self.audit.log(event).await;
                    return AuthResult::InternalError("transaction error".into());
                }
            };

            let credential = match sqlx::query_as::<_, PasswordRow>(
                r#"
                SELECT id, password_hash
                FROM runtime.ephemeral_passwords
                WHERE user_id = $1
                  AND used = FALSE
                  AND revoked = FALSE
                  AND expires_at > now()
                ORDER BY issued_at DESC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                "#,
            )
            .bind(user.id)
            .fetch_optional(&mut *tx)
            .await
            {
                Ok(Some(cred)) => cred,
                Ok(None) => {
                    // No valid password found (or all locked by concurrent requests).
                    let _ = tx.rollback().await;
                    tracing::warn!(dn = %dn, "bind: no valid ephemeral password");
                    self.record_failure(dn, "no_valid_credential").await;
                    let event = AuditEvent::bind_attempt(
                        self.peer_addr,
                        dn,
                        BindOutcome::InvalidCredentials,
                    );
                    self.audit.log(event).await;
                    return AuthResult::InvalidCredentials;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    tracing::error!(dn = %dn, error = %e, "bind: credential lookup failed");
                    let event = AuditEvent::bind_attempt(
                        self.peer_addr,
                        dn,
                        BindOutcome::InternalError {
                            detail: "credential lookup error".into(),
                        },
                    );
                    self.audit.log(event).await;
                    return AuthResult::InternalError("credential lookup error".into());
                }
            };

            // Verify password against stored hash.
            // NIST IA-5: Password material is zeroized after verification.
            let verified = match password::verify_password(
                password_bytes.to_vec(),
                &credential.password_hash,
            ) {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.rollback().await;
                    tracing::error!(dn = %dn, error = %e, "bind: password verification error");
                    let event = AuditEvent::bind_attempt(
                        self.peer_addr,
                        dn,
                        BindOutcome::InternalError {
                            detail: "verification error".into(),
                        },
                    );
                    self.audit.log(event).await;
                    return AuthResult::InternalError("verification error".into());
                }
            };

            if !verified {
                let _ = tx.rollback().await;
                tracing::warn!(dn = %dn, peer = %self.peer_addr, "bind: invalid credentials");
                self.record_failure(dn, "invalid_password").await;
                let event = AuditEvent::bind_attempt(
                    self.peer_addr,
                    dn,
                    BindOutcome::InvalidCredentials,
                );
                self.audit.log(event).await;
                return AuthResult::InvalidCredentials;
            }

            // Mark password as used within the same transaction.
            // NIST IA-5: Ensures one-time use — the FOR UPDATE lock prevents
            // concurrent threads from using this password.
            if let Err(e) = sqlx::query(
                "UPDATE runtime.ephemeral_passwords SET used = TRUE, used_at = now() WHERE id = $1",
            )
            .bind(credential.id)
            .execute(&mut *tx)
            .await
            {
                let _ = tx.rollback().await;
                tracing::error!(
                    dn = %dn,
                    password_id = %credential.id,
                    error = %e,
                    "CRITICAL: failed to mark ephemeral password as used"
                );
                let event = AuditEvent::bind_attempt(
                    self.peer_addr,
                    dn,
                    BindOutcome::InternalError {
                        detail: "failed to mark password used".into(),
                    },
                );
                self.audit.log(event).await;
                return AuthResult::InternalError("failed to mark password used".into());
            }

            // Commit the transaction — password is now atomically consumed.
            if let Err(e) = tx.commit().await {
                tracing::error!(dn = %dn, error = %e, "bind: transaction commit failed");
                let event = AuditEvent::bind_attempt(
                    self.peer_addr,
                    dn,
                    BindOutcome::InternalError {
                        detail: "commit error".into(),
                    },
                );
                self.audit.log(event).await;
                return AuthResult::InternalError("commit error".into());
            }

            // Step 6: Record success.
            self.record_success(dn).await;
            let event = AuditEvent::bind_attempt(
                self.peer_addr,
                dn,
                BindOutcome::Success,
            );
            self.audit.log(event).await;

            tracing::info!(dn = %dn, peer = %self.peer_addr, "bind: success");
            AuthResult::Success
        })
    }
}

impl DatabaseAuthenticator {
    /// Record a successful bind event in the runtime schema.
    async fn record_success(&self, dn: &str) {
        let source_ip = self.peer_addr.ip().to_string();
        if let Err(e) = sqlx::query(
            "INSERT INTO runtime.bind_events (user_dn, source_ip, success) VALUES ($1, $2::inet, TRUE)",
        )
        .bind(dn)
        .bind(&source_ip)
        .execute(self.pool.as_ref())
        .await
        {
            tracing::warn!(error = %e, "failed to record bind success event");
        }
    }

    /// Record a failed bind event in the runtime schema.
    async fn record_failure(&self, dn: &str, reason: &str) {
        let source_ip = self.peer_addr.ip().to_string();
        if let Err(e) = sqlx::query(
            "INSERT INTO runtime.bind_events (user_dn, source_ip, success, failure_reason) VALUES ($1, $2::inet, FALSE, $3)",
        )
        .bind(dn)
        .bind(&source_ip)
        .bind(reason)
        .execute(self.pool.as_ref())
        .await
        {
            tracing::warn!(error = %e, "failed to record bind failure event");
        }
    }
}

// ---------------------------------------------------------------------------
// Database row types (internal)
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct UserRow {
    id: uuid::Uuid,
    username: String,
    dn: String,
    enabled: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct PasswordRow {
    id: uuid::Uuid,
    password_hash: String,
}

// ---------------------------------------------------------------------------
// DatabaseSearchBackend — implements SearchBackend from protocol layer
// ---------------------------------------------------------------------------

use crate::ldap::codec::{Filter, PartialAttribute, ResultCode, SearchScope};
use crate::ldap::search::{DirectoryEntry, SearchBackend, SearchOutcome};

/// Production search backend backed by PostgreSQL identity schema.
///
/// NIST AC-6: Only returns attributes from the identity schema.
/// Never accesses the runtime schema (passwords, bind events, etc.).
pub struct DatabaseSearchBackend {
    pool: Arc<PgPool>,
}

impl DatabaseSearchBackend {
    /// Create a new search backend.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

impl SearchBackend for DatabaseSearchBackend {
    fn search<'a>(
        &'a self,
        base_dn: &'a str,
        _scope: SearchScope,
        filter: &'a Filter,
        requested_attributes: &'a [String],
        size_limit: i32,
        bound_dn: &'a str,
    ) -> Pin<Box<dyn Future<Output = SearchOutcome> + Send + 'a>> {
        Box::pin(async move {
            // NIST AC-3: Log search access for the bound identity.
            tracing::info!(
                bound_dn = %bound_dn,
                base_dn = %base_dn,
                "search: processing request"
            );
            // Build filter criteria from the LDAP filter.
            // For v1, we support a subset: equality on cn/uid/mail, presence of objectClass.
            let (username_filter, email_filter) = extract_simple_filters(filter);

            // Escape LIKE wildcards to prevent wildcard injection.
            // NIST SI-10: Input validation — base_dn must not control LIKE semantics.
            let escaped_dn = base_dn
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let base_dn_pattern = format!("%{}", escaped_dn);
            let effective_limit = if size_limit <= 0 { 100i64 } else { size_limit as i64 };

            // Query users matching the filter under the base DN.
            let users = match sqlx::query_as::<_, SearchUserRow>(
                r#"
                SELECT id, username, display_name, email, dn
                FROM identity.users
                WHERE dn LIKE $1 ESCAPE '\'
                  AND ($2::text IS NULL OR username = $2)
                  AND ($3::text IS NULL OR email = $3)
                  AND enabled = TRUE
                ORDER BY username
                LIMIT $4
                "#,
            )
            .bind(&base_dn_pattern)
            .bind(&username_filter)
            .bind(&email_filter)
            .bind(effective_limit)
            .fetch_all(self.pool.as_ref())
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!(error = %e, "search: database query failed");
                    return SearchOutcome {
                        entries: Vec::new(),
                        result_code: ResultCode::Other,
                        diagnostic: "internal server error".into(),
                    };
                }
            };

            // Convert rows to directory entries with requested attributes.
            let entries: Vec<DirectoryEntry> = users
                .into_iter()
                .map(|row| {
                    let mut attrs = Vec::new();
                    let return_all = requested_attributes.is_empty();

                    if return_all || requested_attributes.iter().any(|a| a.eq_ignore_ascii_case("cn")) {
                        attrs.push(PartialAttribute {
                            attr_type: "cn".to_string(),
                            values: vec![row.username.as_bytes().to_vec()],
                        });
                    }
                    if return_all || requested_attributes.iter().any(|a| a.eq_ignore_ascii_case("uid")) {
                        attrs.push(PartialAttribute {
                            attr_type: "uid".to_string(),
                            values: vec![row.username.as_bytes().to_vec()],
                        });
                    }
                    if return_all || requested_attributes.iter().any(|a| a.eq_ignore_ascii_case("displayName")) {
                        if let Some(ref dn) = row.display_name {
                            attrs.push(PartialAttribute {
                                attr_type: "displayName".to_string(),
                                values: vec![dn.as_bytes().to_vec()],
                            });
                        }
                    }
                    if return_all || requested_attributes.iter().any(|a| a.eq_ignore_ascii_case("mail")) {
                        if let Some(ref email) = row.email {
                            attrs.push(PartialAttribute {
                                attr_type: "mail".to_string(),
                                values: vec![email.as_bytes().to_vec()],
                            });
                        }
                    }
                    if return_all || requested_attributes.iter().any(|a| a.eq_ignore_ascii_case("objectClass")) {
                        attrs.push(PartialAttribute {
                            attr_type: "objectClass".to_string(),
                            values: vec![
                                b"top".to_vec(),
                                b"inetOrgPerson".to_vec(),
                            ],
                        });
                    }

                    DirectoryEntry {
                        dn: row.dn,
                        attributes: attrs,
                    }
                })
                .collect();

            SearchOutcome {
                entries,
                result_code: ResultCode::Success,
                diagnostic: String::new(),
            }
        })
    }
}

/// Extract simple equality filter values from an LDAP filter tree.
///
/// For v1, we handle:
/// - (uid=value) or (cn=value) -> username filter
/// - (mail=value) -> email filter
/// - (objectClass=*) -> no filter (match all)
/// - AND combinations of the above
///
/// Complex filters (OR, NOT, substring, approx) are ignored and result
/// in unfiltered queries, which is safe (returns too many results rather
/// than too few).
fn extract_simple_filters(filter: &Filter) -> (Option<String>, Option<String>) {
    match filter {
        Filter::EqualityMatch(ava) => {
            let attr = ava.attribute_desc.to_lowercase();
            let value = String::from_utf8_lossy(&ava.assertion_value).to_string();
            match attr.as_str() {
                "uid" | "cn" => (Some(value), None),
                "mail" => (None, Some(value)),
                _ => (None, None),
            }
        }
        Filter::And(filters) => {
            let mut username = None;
            let mut email = None;
            for f in filters {
                let (u, e) = extract_simple_filters(f);
                if u.is_some() {
                    username = u;
                }
                if e.is_some() {
                    email = e;
                }
            }
            (username, email)
        }
        _ => (None, None),
    }
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct SearchUserRow {
    id: uuid::Uuid,
    username: String,
    display_name: Option<String>,
    email: Option<String>,
    dn: String,
}

// ---------------------------------------------------------------------------
// DatabasePasswordStore — implements PasswordStore from protocol layer
// ---------------------------------------------------------------------------

use crate::ldap::password::{PasswordModifyResult, PasswordStore};

/// Production password store backed by PostgreSQL runtime schema.
///
/// NIST IA-5(1): Passwords set through this store are hashed with argon2id
/// before storage. Plaintext is zeroized after hashing.
pub struct DatabasePasswordStore {
    pool: Arc<PgPool>,
    password_ttl_secs: u64,
}

impl DatabasePasswordStore {
    /// Create a new password store.
    pub fn new(pool: Arc<PgPool>, password_ttl_secs: u64) -> Self {
        Self {
            pool,
            password_ttl_secs,
        }
    }
}

impl PasswordStore for DatabasePasswordStore {
    fn set_password<'a>(
        &'a self,
        user_dn: &'a str,
        new_password: &'a [u8],
        broker_dn: &'a str,
    ) -> Pin<Box<dyn Future<Output = PasswordModifyResult> + Send + 'a>> {
        Box::pin(async move {
            // Look up user by DN to get user_id.
            let user_id = match sqlx::query_scalar::<_, uuid::Uuid>(
                "SELECT id FROM identity.users WHERE dn = $1",
            )
            .bind(user_dn)
            .fetch_optional(self.pool.as_ref())
            .await
            {
                Ok(Some(id)) => id,
                Ok(None) => return PasswordModifyResult::UserNotFound,
                Err(e) => return PasswordModifyResult::InternalError(e.to_string()),
            };

            // Hash the new password with argon2id.
            // NIST IA-5(1): Plaintext is zeroized inside hash_password().
            let hash = match password::hash_password(new_password.to_vec()) {
                Ok(h) => h,
                Err(e) => return PasswordModifyResult::InternalError(e.to_string()),
            };

            // Store the hashed password in the runtime schema.
            let result = sqlx::query(
                r#"
                INSERT INTO runtime.ephemeral_passwords
                    (user_id, password_hash, issued_by, expires_at)
                VALUES
                    ($1, $2, $3, now() + make_interval(secs => $4::double precision))
                "#,
            )
            .bind(user_id)
            .bind(&hash)
            .bind(broker_dn)
            .bind(self.password_ttl_secs as f64)
            .execute(self.pool.as_ref())
            .await;

            match result {
                Ok(_) => {
                    tracing::info!(
                        target_dn = %user_dn,
                        broker_dn = %broker_dn,
                        ttl_secs = self.password_ttl_secs,
                        "ephemeral password stored"
                    );
                    PasswordModifyResult::Success
                }
                Err(e) => PasswordModifyResult::InternalError(e.to_string()),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// ConfigBrokerAuthorizer — implements BrokerAuthorizer from protocol layer
// ---------------------------------------------------------------------------

use crate::ldap::password::BrokerAuthorizer;

/// Broker authorizer backed by a static list of authorized DNs from configuration.
///
/// NIST AC-3: Only DNs listed in the security.broker_dns configuration are
/// permitted to invoke the Password Modify extended operation.
pub struct ConfigBrokerAuthorizer {
    authorized_dns: Vec<String>,
}

impl ConfigBrokerAuthorizer {
    /// Create a new authorizer from a list of authorized broker DNs.
    pub fn new(authorized_dns: Vec<String>) -> Self {
        Self { authorized_dns }
    }

    /// Return a reference to the authorized DNs list.
    pub fn authorized_dns_ref(&self) -> &[String] {
        &self.authorized_dns
    }
}

impl BrokerAuthorizer for ConfigBrokerAuthorizer {
    fn is_authorized_broker(&self, dn: &str) -> bool {
        self.authorized_dns.iter().any(|d| d == dn)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_broker_authorizer() {
        let auth = ConfigBrokerAuthorizer::new(vec![
            "cn=broker,ou=services,dc=example,dc=com".to_string(),
        ]);
        assert!(auth.is_authorized_broker("cn=broker,ou=services,dc=example,dc=com"));
        assert!(!auth.is_authorized_broker("cn=attacker,dc=example,dc=com"));
        assert!(!auth.is_authorized_broker(""));
    }

    #[test]
    fn test_extract_uid_filter() {
        let filter = Filter::EqualityMatch(crate::ldap::codec::AttributeValueAssertion {
            attribute_desc: "uid".to_string(),
            assertion_value: b"jdoe".to_vec(),
        });
        let (username, email) = extract_simple_filters(&filter);
        assert_eq!(username.as_deref(), Some("jdoe"));
        assert!(email.is_none());
    }

    #[test]
    fn test_extract_mail_filter() {
        let filter = Filter::EqualityMatch(crate::ldap::codec::AttributeValueAssertion {
            attribute_desc: "mail".to_string(),
            assertion_value: b"jdoe@example.com".to_vec(),
        });
        let (username, email) = extract_simple_filters(&filter);
        assert!(username.is_none());
        assert_eq!(email.as_deref(), Some("jdoe@example.com"));
    }

    #[test]
    fn test_extract_and_filter() {
        let filter = Filter::And(vec![
            Filter::EqualityMatch(crate::ldap::codec::AttributeValueAssertion {
                attribute_desc: "uid".to_string(),
                assertion_value: b"jdoe".to_vec(),
            }),
            Filter::EqualityMatch(crate::ldap::codec::AttributeValueAssertion {
                attribute_desc: "mail".to_string(),
                assertion_value: b"jdoe@example.com".to_vec(),
            }),
        ]);
        let (username, email) = extract_simple_filters(&filter);
        assert_eq!(username.as_deref(), Some("jdoe"));
        assert_eq!(email.as_deref(), Some("jdoe@example.com"));
    }
}
