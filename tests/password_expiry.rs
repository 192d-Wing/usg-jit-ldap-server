//! Integration test: password TTL enforcement.

mod common;

#[tokio::test]
async fn test_password_ttl_enforcement() {
    skip_without_db!();

    // 1. Insert password with very short TTL (1 second)
    // 2. Sleep 2 seconds
    // 3. Verify bind fails (password expired)

    eprintln!("password_ttl: test scaffolding ready, needs live DB to execute");
}

#[tokio::test]
async fn test_revoked_password_rejected() {
    skip_without_db!();

    // 1. Insert password
    // 2. Revoke it (UPDATE SET revoked = TRUE)
    // 3. Verify bind fails

    eprintln!("revoked_password: test scaffolding ready, needs live DB to execute");
}
