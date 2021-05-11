//! Cryptographically random nonces.
use serde::*;

use crate::types::*;

#[allow(unused)]
/// A random nonce.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce;

#[allow(unused)]
impl Nonce {
    /// Generates a new cryptographically random nonce with the given random number generator.
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}
