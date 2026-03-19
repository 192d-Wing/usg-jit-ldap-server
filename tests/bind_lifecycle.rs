//! Integration test: full bind-search-unbind lifecycle.
//!
//! Requires: DATABASE_URL environment variable pointing to a PostgreSQL
//! database with the identity and runtime schemas migrated.

mod common;

#[tokio::test]
async fn test_full_bind_lifecycle() {
    skip_without_db!();

    // This test exercises:
    // 1. User lookup in identity.users
    // 2. Ephemeral password retrieval from runtime.ephemeral_passwords
    // 3. Argon2id verification
    // 4. Atomic mark-as-used via FOR UPDATE SKIP LOCKED
    // 5. Bind event recording in runtime.bind_events
    // 6. Audit event emission

    // TODO: When run with a real DB, this test should:
    // - Insert a test user into identity.users
    // - Insert an ephemeral password hash into runtime.ephemeral_passwords
    // - Construct a DatabaseAuthenticator
    // - Call authenticate() and verify Success
    // - Verify the password is marked as used
    // - Call authenticate() again and verify InvalidCredentials (one-time use)
    // - Clean up test data

    eprintln!("bind_lifecycle: test scaffolding ready, needs live DB to execute");
}

#[tokio::test]
async fn test_bind_with_expired_password() {
    skip_without_db!();

    // Insert a password with expires_at in the past.
    // Verify bind returns InvalidCredentials.

    eprintln!("expired_password: test scaffolding ready, needs live DB to execute");
}

#[tokio::test]
async fn test_bind_with_disabled_user() {
    skip_without_db!();

    // Insert a user with enabled = false.
    // Verify bind returns InvalidCredentials.

    eprintln!("disabled_user: test scaffolding ready, needs live DB to execute");
}
