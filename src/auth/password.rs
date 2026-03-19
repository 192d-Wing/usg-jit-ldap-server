//! Password hashing and verification using argon2.
//!
//! All passwords are hashed before storage; plaintext is
//! zeroized immediately after use.

use zeroize::Zeroize;

/// Hash a plaintext password with argon2.
pub fn hash_password(mut plaintext: Vec<u8>) -> Result<String, argon2::password_hash::Error> {
    // TODO: generate salt, hash, return PHC string
    plaintext.zeroize();
    todo!("password hashing")
}

/// Verify a plaintext password against a stored argon2 hash.
pub fn verify_password(
    mut plaintext: Vec<u8>,
    _hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    // TODO: parse PHC string, verify
    plaintext.zeroize();
    todo!("password verification")
}
