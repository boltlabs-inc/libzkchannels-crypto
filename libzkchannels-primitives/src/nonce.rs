use crate::types::*;

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub struct Nonce;

#[allow(unused)]
impl Nonce {
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}
