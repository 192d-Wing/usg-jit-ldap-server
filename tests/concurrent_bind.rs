//! Integration test: concurrent bind with same ephemeral password.
//!
//! This is the critical test for the C-4 race condition fix.
//! Multiple tasks attempt to authenticate with the same one-time password
//! simultaneously. Only one should succeed.

mod common;

#[tokio::test]
async fn test_concurrent_bind_same_password() {
    skip_without_db!();
    let pool = common::setup_test_pool().await;
    common::cleanup_test_data(&pool).await;

    let dn = "cn=concurrent-test,ou=users,dc=test,dc=com";
    let user_id = common::insert_test_user(&pool, dn, "concurrent-test").await;
    common::insert_ephemeral_password(&pool, user_id, "one-time-pass", 3600).await;

    let pool_arc = std::sync::Arc::new(pool.clone());

    use usg_jit_ldap_server::ldap::bind::{AuthResult, Authenticator};

    // Spawn 10 concurrent bind attempts
    let mut handles = Vec::new();
    for i in 0..10u8 {
        let pool = pool_arc.clone();
        let dn = dn.to_string();
        handles.push(tokio::spawn(async move {
            let rate_limiter =
                usg_jit_ldap_server::auth::rate_limit::RateLimiter::new(pool.clone(), 100, 300);
            let audit = usg_jit_ldap_server::audit::AuditLogger::tracing_only();
            let peer = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, i.wrapping_add(1))),
                54321,
            );
            let auth = usg_jit_ldap_server::auth::DatabaseAuthenticator::new(
                pool.clone(),
                rate_limiter,
                usg_jit_ldap_server::auth::rate_limit::BindIpRateLimiter::new(pool, 50, 300),
                audit,
                peer,
            );
            auth.authenticate(&dn, b"one-time-pass").await
        }));
    }

    let results: Vec<AuthResult> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let successes = results
        .iter()
        .filter(|r| matches!(r, AuthResult::Success))
        .count();
    assert_eq!(
        successes, 1,
        "exactly one concurrent bind should succeed, got {}",
        successes
    );

    common::cleanup_test_data(&pool).await;
}
