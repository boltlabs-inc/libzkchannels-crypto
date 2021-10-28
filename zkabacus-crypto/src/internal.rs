use crate::revlock::RevocationPair;
use crate::{Nonce, Rng};

/// Generate a new cryptographically random nonce with the given random number generator. This
/// is not a part of the public API and may change between major releases.
pub fn test_new_nonce(rng: &mut impl Rng) -> Nonce {
    Nonce::new(rng)
}

/// Create a new, random revocation pair. This is not a part of the public API and may change
/// between major releases.
pub fn test_new_revocation_pair(rng: &mut impl Rng) -> RevocationPair {
    RevocationPair::new(rng)
}
