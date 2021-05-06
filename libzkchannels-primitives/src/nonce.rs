use serde::*;

use crate::types::*;

#[allow(unused)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce;

#[allow(unused)]
impl Nonce {
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}
