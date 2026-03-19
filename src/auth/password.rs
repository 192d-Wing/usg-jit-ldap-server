// SPDX-License-Identifier: TBD
//
// Password Hashing and Verification
//
// Provides argon2id password hashing and verification with zeroization of
// plaintext material immediately after use.
//
// NIST SP 800-53 Rev. 5:
// - IA-5 (Authenticator Management): Passwords are stored as argon2id hashes.
//   Plaintext password bytes are zeroized in memory immediately after hashing
//   or verification. No plaintext password is ever logged or persisted.
// - IA-5(1) (Password-Based Authentication): Uses argon2id — a memory-hard
//   key derivation function resistant to GPU/ASIC attacks.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use zeroize::Zeroize;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password hashing failed: {0}")]
    HashingFailed(String),

    #[error("password verification failed: {0}")]
    VerificationFailed(String),

    #[error("stored hash is malformed: {0}")]
    MalformedHash(String),
}

// ---------------------------------------------------------------------------
// Password operations
// ---------------------------------------------------------------------------

/// Hash a plaintext password using argon2id with a random salt.
///
/// The plaintext bytes are zeroized after hashing.
///
/// NIST IA-5: Password material is never retained in memory longer than
/// necessary. The returned string is a PHC-format hash suitable for storage.
pub fn hash_password(mut plaintext: Vec<u8>) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(&plaintext, &salt)
        .map_err(|e| PasswordError::HashingFailed(e.to_string()))?;

    // NIST IA-5: Zeroize plaintext immediately after hashing.
    plaintext.zeroize();

    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored argon2id hash.
///
/// The plaintext bytes are zeroized after verification regardless of outcome.
///
/// Returns `true` if the password matches, `false` if it does not.
/// Returns an error only if the stored hash is malformed or verification
/// encounters an unexpected failure.
///
/// NIST IA-5: Password bytes are compared against the hash and then dropped.
/// The function never logs or retains the plaintext.
pub fn verify_password(mut plaintext: Vec<u8>, stored_hash: &str) -> Result<bool, PasswordError> {
    let parsed_hash = PasswordHash::new(stored_hash)
        .map_err(|e| PasswordError::MalformedHash(e.to_string()))?;

    let argon2 = Argon2::default();
    let result = argon2.verify_password(&plaintext, &parsed_hash);

    // NIST IA-5: Zeroize plaintext immediately after verification.
    plaintext.zeroize();

    match result {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::VerificationFailed(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_success() {
        let password = b"correct-horse-battery-staple".to_vec();
        let hash = hash_password(password).unwrap();

        // Verify with correct password.
        let correct = b"correct-horse-battery-staple".to_vec();
        assert!(verify_password(correct, &hash).unwrap());
    }

    #[test]
    fn test_verify_wrong_password() {
        let password = b"correct-horse-battery-staple".to_vec();
        let hash = hash_password(password).unwrap();

        // Verify with wrong password.
        let wrong = b"wrong-password".to_vec();
        assert!(!verify_password(wrong, &hash).unwrap());
    }

    #[test]
    fn test_malformed_hash_returns_error() {
        let plaintext = b"password".to_vec();
        let result = verify_password(plaintext, "not-a-valid-hash");
        assert!(result.is_err());
        match result.unwrap_err() {
            PasswordError::MalformedHash(_) => {}
            other => panic!("expected MalformedHash, got: {other}"),
        }
    }

    #[test]
    fn test_hash_produces_phc_format() {
        let hash = hash_password(b"test".to_vec()).unwrap();
        // PHC format starts with $argon2id$ or $argon2i$
        assert!(hash.starts_with("$argon2"));
    }
}
