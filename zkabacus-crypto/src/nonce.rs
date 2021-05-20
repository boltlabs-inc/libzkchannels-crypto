//! Cryptographically random nonces.
use crate::types::*;
use ::serde::*;

use crate::Rng;

#[allow(unused)]
/// A random nonce.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(#[serde(with = "SerializeElement")] Scalar);

#[allow(unused)]
impl Nonce {
    /// Generate a new cryptographically random nonce with the given random number generator.
    pub(crate) fn new(_rng: &mut impl Rng) -> Self {
        todo!();
    }
}
