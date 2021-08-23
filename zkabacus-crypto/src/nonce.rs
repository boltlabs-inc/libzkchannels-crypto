//! Cryptographically random nonces.
use crate::{types::*, Rng, CLOSE_SCALAR};
use ff::Field;
use serde::*;
use std::ops::Not;
use subtle::ConstantTimeEq;
use zkchannels_crypto::SerializeElement;

/// A random nonce.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(#[serde(with = "SerializeElement")] Scalar);

impl Nonce {
    /// Generate a new cryptographically random nonce with the given random number generator.
    pub(crate) fn new(rng: &mut impl Rng) -> Self {
        let mut get_well_formed_nonce = || loop {
            let n = Self(Scalar::random(&mut *rng));
            if n.is_well_formed() {
                return n;
            }
        };

        // Try until a well-formed nonce is generated
        get_well_formed_nonce()
    }

    /// Convert a nonce to its canonical `Scalar` representation.
    pub(crate) fn as_scalar(&self) -> Scalar {
        self.0
    }

    /// Returns true if and only if the scalar representation of the nonce
    /// is not the domain separator [`CLOSE_SCALAR`].
    pub fn is_well_formed(&self) -> bool {
        self.as_scalar().ct_eq(&CLOSE_SCALAR).not().into()
    }
}

#[cfg(feature = "sqlite")]
zkchannels_crypto::impl_sqlx_for_bincode_ty!(Nonce);

#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;

    // Sanity check on invalid nonce
    #[test]
    fn close_scalar_as_nonce() {
        let bad_nonce = Nonce(CLOSE_SCALAR);
        assert!(!bad_nonce.is_well_formed());
    }

    // Sanity check on new nonce
    #[test]
    fn create_nonce() {
        let nonce = Nonce::new(&mut thread_rng());
        assert!(nonce.is_well_formed());
    }
}
