//! Cryptographically random nonces.
use crate::{types::*, Rng};
use ff::Field;
use serde::*;
use zkchannels_crypto::SerializeElement;

/// A random nonce.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(#[serde(with = "SerializeElement")] Scalar);

impl Nonce {
    /// Generate a new cryptographically random nonce with the given random number generator.
    pub(crate) fn new(rng: &mut impl Rng) -> Self {
        Self(Scalar::random(rng))
    }

    /// Convert a nonce to its canonical `Scalar` representation.
    pub(crate) fn as_scalar(&self) -> Scalar {
        self.0
    }
}

#[cfg(feature = "sqlite")]
zkchannels_crypto::impl_sqlx_for_bincode_ty!(Nonce);
