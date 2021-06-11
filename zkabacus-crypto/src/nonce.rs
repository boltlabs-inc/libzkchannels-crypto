//! Cryptographically random nonces.
use crate::{types::*, Rng};
use ff::Field;
use serde::*;
use zkchannels_crypto::SerializeElement;

#[allow(unused)]
/// A random nonce.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(#[serde(with = "SerializeElement")] pub(crate) Scalar);

#[allow(unused)]
impl Nonce {
    /// Generate a new cryptographically random nonce with the given random number generator. This
    /// is not part of the public API and may change between major releases.
    #[doc(hidden)]
    pub fn new(rng: &mut impl Rng) -> Self {
        Self(Scalar::random(rng))
    }

    /// Convert a nonce to its canonical `Scalar` representation.
    pub(crate) fn to_scalar(&self) -> Scalar {
        self.0
    }
}
