//! Cryptographically random nonces.
use serde::*;

use crate::Rng;

#[allow(unused)]
/// A random nonce.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(());

#[allow(unused)]
impl Nonce {
    /// Generate a new cryptographically random nonce with the given random number generator.
    pub fn new(_rng: &mut impl Rng) -> Self {
        todo!();
    }
}
