//! Integration test: password TTL enforcement and revocation.

mod common;

#[tokio::test]
async fn test_password_ttl_enforcement() {
    skip_without_db!();
    let pool = common::setup_test_pool().await;
    common::cleanup_test_data(&pool).await;

    let dn = "cn=ttl-test,ou=users,dc=test,dc=com";
    let user_id = common::insert_test_user(&pool, dn, "ttl-test").await;
    // Insert password with very short TTL (1 second)
    common::insert_ephemeral_password(&pool, user_id, "short-lived-pass", 1).await;

    // Wait for the password to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let pool_arc = std::sync::Arc::new(pool.clone());
    let auth = usg_jit_ldap_server::auth::DatabaseAuthenticator::new(
        pool_arc.clone(),
        usg_jit_ldap_server::auth::rate_limit::RateLimiter::new(pool_arc.clone(), 10, 300),
        usg_jit_ldap_server::auth::rate_limit::BindIpRateLimiter::new(pool_arc.clone(), 50, 300),
        usg_jit_ldap_server::audit::AuditLogger::tracing_only(),
        common::test_addr(),
    );

    use usg_jit_ldap_server::ldap::bind::Authenticator;
    let result = auth.authenticate(dn, b"short-lived-pass").await;
    assert!(
        matches!(
            result,
            usg_jit_ldap_server::ldap::bind::AuthResult::InvalidCredentials
        ),
        "expired password (TTL) should be rejected, got: {:?}",
        result
    );

    common::cleanup_test_data(&pool).await;
}

#[tokio::test]
async fn test_revoked_password_rejected() {
    skip_without_db!();
    let pool = common::setup_test_pool().await;
    common::cleanup_test_data(&pool).await;

    let dn = "cn=revoke-test,ou=users,dc=test,dc=com";
    let user_id = common::insert_test_user(&pool, dn, "revoke-test").await;
    let pw_id = common::insert_ephemeral_password(&pool, user_id, "revocable-pass", 3600).await;

    // Revoke the password
    sqlx::query("UPDATE runtime.ephemeral_passwords SET revoked = TRUE WHERE id = $1")
        .bind(pw_id)
        .execute(&pool)
        .await
        .unwrap();

    let pool_arc = std::sync::Arc::new(pool.clone());
    let auth = usg_jit_ldap_server::auth::DatabaseAuthenticator::new(
        pool_arc.clone(),
        usg_jit_ldap_server::auth::rate_limit::RateLimiter::new(pool_arc.clone(), 10, 300),
        usg_jit_ldap_server::auth::rate_limit::BindIpRateLimiter::new(pool_arc.clone(), 50, 300),
        usg_jit_ldap_server::audit::AuditLogger::tracing_only(),
        common::test_addr(),
    );

    use usg_jit_ldap_server::ldap::bind::Authenticator;
    let result = auth.authenticate(dn, b"revocable-pass").await;
    assert!(
        matches!(
            result,
            usg_jit_ldap_server::ldap::bind::AuthResult::InvalidCredentials
        ),
        "revoked password should be rejected, got: {:?}",
        result
    );

    common::cleanup_test_data(&pool).await;
}
