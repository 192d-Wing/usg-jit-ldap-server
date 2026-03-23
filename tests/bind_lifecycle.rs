//! Integration test: full bind-search-unbind lifecycle.
//!
//! Requires: DATABASE_URL environment variable pointing to a PostgreSQL
//! database with the identity and runtime schemas migrated.

mod common;

#[tokio::test]
async fn test_full_bind_lifecycle() {
    skip_without_db!();
    let pool = common::setup_test_pool().await;
    common::cleanup_test_data(&pool).await;

    let dn = "cn=lifecycle-test,ou=users,dc=test,dc=com";
    let user_id = common::insert_test_user(&pool, dn, "lifecycle-test").await;
    common::insert_ephemeral_password(&pool, user_id, "correct-password", 3600).await;

    // Build authenticator
    let pool_arc = std::sync::Arc::new(pool.clone());
    let rate_limiter =
        usg_jit_ldap_server::auth::rate_limit::RateLimiter::new(pool_arc.clone(), 10, 300);
    let audit = usg_jit_ldap_server::audit::AuditLogger::tracing_only();
    let peer_addr = common::test_addr();
    let auth = usg_jit_ldap_server::auth::DatabaseAuthenticator::new(
        pool_arc.clone(),
        rate_limiter,
        usg_jit_ldap_server::auth::rate_limit::BindIpRateLimiter::new(pool_arc.clone(), 50, 300),
        audit,
        peer_addr,
        None,
    );

    use usg_jit_ldap_server::ldap::bind::Authenticator;

    // First bind: should succeed
    let result = auth.authenticate(dn, b"correct-password").await;
    assert!(
        matches!(result, usg_jit_ldap_server::ldap::bind::AuthResult::Success),
        "first bind should succeed, got: {:?}",
        result
    );

    // Second bind with same password: should fail (one-time use)
    let auth2 = usg_jit_ldap_server::auth::DatabaseAuthenticator::new(
        pool_arc.clone(),
        usg_jit_ldap_server::auth::rate_limit::RateLimiter::new(pool_arc.clone(), 10, 300),
        usg_jit_ldap_server::auth::rate_limit::BindIpRateLimiter::new(pool_arc.clone(), 50, 300),
        usg_jit_ldap_server::audit::AuditLogger::tracing_only(),
        peer_addr,
        None,
    );
    let result2 = auth2.authenticate(dn, b"correct-password").await;
    assert!(
        matches!(
            result2,
            usg_jit_ldap_server::ldap::bind::AuthResult::InvalidCredentials
        ),
        "second bind should fail (one-time use), got: {:?}",
        result2
    );

    common::cleanup_test_data(&pool).await;
}

#[tokio::test]
async fn test_bind_with_expired_password() {
    skip_without_db!();
    let pool = common::setup_test_pool().await;
    common::cleanup_test_data(&pool).await;

    let dn = "cn=expiry-test,ou=users,dc=test,dc=com";
    let user_id = common::insert_test_user(&pool, dn, "expiry-test").await;
    // Insert password that's already expired (negative TTL uses past dates)
    common::insert_ephemeral_password(&pool, user_id, "expired-pass", -1).await;

    let pool_arc = std::sync::Arc::new(pool.clone());
    let auth = usg_jit_ldap_server::auth::DatabaseAuthenticator::new(
        pool_arc.clone(),
        usg_jit_ldap_server::auth::rate_limit::RateLimiter::new(pool_arc.clone(), 10, 300),
        usg_jit_ldap_server::auth::rate_limit::BindIpRateLimiter::new(pool_arc.clone(), 50, 300),
        usg_jit_ldap_server::audit::AuditLogger::tracing_only(),
        common::test_addr(),
        None,
    );

    use usg_jit_ldap_server::ldap::bind::Authenticator;
    let result = auth.authenticate(dn, b"expired-pass").await;
    assert!(
        matches!(
            result,
            usg_jit_ldap_server::ldap::bind::AuthResult::InvalidCredentials
        ),
        "expired password should be rejected, got: {:?}",
        result
    );

    common::cleanup_test_data(&pool).await;
}

#[tokio::test]
async fn test_bind_with_disabled_user() {
    skip_without_db!();
    let pool = common::setup_test_pool().await;
    common::cleanup_test_data(&pool).await;

    let dn = "cn=disabled-test,ou=users,dc=test,dc=com";
    let user_id = common::insert_test_user(&pool, dn, "disabled-test").await;
    // Disable the user
    sqlx::query("UPDATE identity.users SET enabled = false WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    common::insert_ephemeral_password(&pool, user_id, "valid-pass", 3600).await;

    let pool_arc = std::sync::Arc::new(pool.clone());
    let auth = usg_jit_ldap_server::auth::DatabaseAuthenticator::new(
        pool_arc.clone(),
        usg_jit_ldap_server::auth::rate_limit::RateLimiter::new(pool_arc.clone(), 10, 300),
        usg_jit_ldap_server::auth::rate_limit::BindIpRateLimiter::new(pool_arc.clone(), 50, 300),
        usg_jit_ldap_server::audit::AuditLogger::tracing_only(),
        common::test_addr(),
        None,
    );

    use usg_jit_ldap_server::ldap::bind::Authenticator;
    let result = auth.authenticate(dn, b"valid-pass").await;
    assert!(
        matches!(
            result,
            usg_jit_ldap_server::ldap::bind::AuthResult::InvalidCredentials
        ),
        "disabled user should be rejected, got: {:?}",
        result
    );

    common::cleanup_test_data(&pool).await;
}
