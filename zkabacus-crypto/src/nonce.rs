//! Cryptographically random nonces.
use crate::{types::*, Rng, CLOSE_SCALAR};
use ff::Field;
use serde::*;
use std::convert::TryFrom;
use zkchannels_crypto::SerializeElement;

/// A random nonce.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedNonce")]
pub struct Nonce(#[serde(with = "SerializeElement")] Scalar);

#[derive(Debug, Deserialize)]
struct UncheckedNonce(#[serde(with = "SerializeElement")] Scalar);

impl TryFrom<UncheckedNonce> for Nonce {
    type Error = String;

    /// Try to convert an unchecked nonce to a nonce.
    fn try_from(unchecked: UncheckedNonce) -> Result<Self, Self::Error> {
        let n = unchecked.0;
        if n != CLOSE_SCALAR {
            Ok(Self(n))
        } else {
            Err("The nonce cannot be the close scalar.".to_string())
        }
    }
}

impl Nonce {
    /// Generate a new cryptographically random nonce with the given random number generator.
    pub(crate) fn new(rng: &mut impl Rng) -> Self {
        loop {
            if let Ok(n) = Nonce::try_from(UncheckedNonce(Scalar::random(&mut *rng))) {
                return n;
            }
        }
    }

    /// Convert a nonce to its canonical `Scalar` representation.
    pub(crate) fn as_scalar(&self) -> Scalar {
        self.0
    }
}

#[cfg(feature = "sqlite")]
zkchannels_crypto::impl_sqlx_for_bincode_ty!(Nonce);

#[cfg(test)]
mod test {
    #[cfg(feature = "bincode")]
    use {super::*, rand::thread_rng};

    // Sanity check on invalid nonce
    #[test]
    #[cfg(feature = "bincode")]
    fn run_serialize_deserialize_nonce() {
        // Check validation when serialized unchecked nonce is the close scalar
        let bad_nonce = Nonce(CLOSE_SCALAR);
        let serialized_bad_nonce = bincode::serialize(&bad_nonce).unwrap();
        assert!(bincode::deserialize::<Nonce>(&serialized_bad_nonce).is_err());

        // Check normal serialization/deserializtion
        let nonce = Nonce::new(&mut thread_rng());
        let serialized_nonce = bincode::serialize(&nonce).unwrap();
        let deserialized_nonce = bincode::deserialize(&serialized_nonce).unwrap();
        assert_eq!(nonce, deserialized_nonce);
    }
}
