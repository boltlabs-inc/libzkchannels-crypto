// Implementation of Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381
use crate::{signatures::*, types::*};
use rand::CryptoRng;
use rand_core::RngCore;

#[derive(Debug)]
pub(crate) struct BlindSecretKey {}

#[derive(Debug, Clone)]
pub struct BlindPublicKey {}

#[derive(Debug)]
pub struct BlindKeyPair {
    sk: BlindSecretKey,
    pub pk: BlindPublicKey,
}

#[derive(Debug, Clone)]
pub struct BlindedMessage {}

#[derive(Debug, Clone)]
pub struct BlindedSignature {}

#[derive(Debug, Clone, Copy)]
pub struct BlindingFactor(pub Scalar);

impl BlindedSignature {
    /// Generates a blinded signature and corresponding blinding factor
    pub fn from(_rng: &mut (impl CryptoRng + RngCore), _sig: Signature) -> (Self, BlindingFactor) {
        todo!();
    }

    /// Unblinds a signature. This will always compute: the user must take care to use
    /// a blinding factor that actually corresponds to the signature in order to retrieve
    /// a valid Signature on the original message.
    pub fn unblind(&self, _bf: &BlindingFactor) -> Signature {
        todo!()
    }

    /// Randomizes signature in-place.
    pub fn randomize(&mut self, _rng: &mut (impl CryptoRng + RngCore)) {
        todo!()
    }
}

#[allow(dead_code)]
impl BlindSecretKey {
    fn new(_rng: &mut (impl CryptoRng + RngCore), _length: usize, _g: G1Projective) -> Self {
        todo!();
    }

    fn from_secret_key(_sk: &SecretKey, _g: G1Projective) -> Self {
        todo!();
    }

    fn try_blind_sign(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _msg: &BlindedMessage,
    ) -> Result<BlindedSignature, String> {
        todo!();
    }
}

impl BlindPublicKey {
    #[allow(dead_code)]
    fn from_secret_key(
        _rng: &mut (impl CryptoRng + RngCore),
        _sk: &BlindSecretKey,
        _g: &G1Projective,
    ) -> Self {
        todo!();
    }

    /// Generates a blinded message and corresponding blinding factor
    pub fn blind_message(
        _rng: &mut (impl CryptoRng + RngCore),
        _msg: &Message,
    ) -> (BlindedMessage, BlindingFactor) {
        todo!();
    }

    pub fn blind_verify(&self, _msg: &Message, _sig: &BlindedSignature, _bf: &Scalar) -> bool {
        todo!();
    }
}

impl BlindKeyPair {
    pub fn new(_length: usize, _rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }

    pub fn from_keypair(_rng: &mut (impl CryptoRng + RngCore), _kp: &KeyPair) -> Self {
        todo!();
    }

    pub fn try_blind_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &BlindedMessage,
    ) -> Result<BlindedSignature, String> {
        self.sk.try_blind_sign(rng, msg)
    }
}
