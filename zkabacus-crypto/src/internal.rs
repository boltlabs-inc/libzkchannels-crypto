use crate::revlock::{RevocationLock, RevocationSecret};
use crate::{Nonce, Rng, Verification};

/// Generate a new cryptographically random nonce with the given random number generator. This
/// is not a part of the public API and may change between major releases.
pub fn test_new_nonce(rng: &mut impl Rng) -> Nonce {
    Nonce::new(rng)
}

/// Create a new, random revocation secret. This is not a part of the public API and may change
/// between major releases.
pub fn test_new_revocation_secret(rng: &mut impl Rng) -> RevocationSecret {
    RevocationSecret::new(rng)
}

/// Derive the [`RevocationLock`] corresponding to this [`RevocationSecret`]. This is not a
/// part of the public API and may change between major releases.
pub fn test_new_revocation_lock(secret: &RevocationSecret) -> RevocationLock {
    secret.revocation_lock()
}

/// Validate a revocation pair. This is not a part of the public API and may change between
/// major releases.
pub fn test_verify_pair(lock: &RevocationLock, secret: &RevocationSecret) -> Verification {
    lock.verify(secret)
}
