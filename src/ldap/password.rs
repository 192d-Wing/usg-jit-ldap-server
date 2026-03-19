//! LDAP Password Modify Extended Operation (RFC 3062).
//!
//! Handles password change requests, hashes new passwords with
//! argon2, and updates the credential store.

/// Process a password-modify extended operation.
pub async fn handle_password_modify(
    _dn: &str,
    _old_password: Option<&[u8]>,
    _new_password: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: verify old password if provided, hash new, store
    todo!("password modify handler")
}
