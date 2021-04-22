// Implementation of Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381
use crate::{signatures::*, types::*};
use rand::CryptoRng;
use rand_core::RngCore;

/// Pointcheval-Sanders secret key for blind multi-message signing
#[derive(Debug)]
pub(crate) struct BlindSecretKey {}

/// Pointcheval-Sanders public key for blind multi-message verifying
#[derive(Debug, Clone)]
pub struct BlindPublicKey {}

/// Pointcheval-Sanders keypair for blinded operations
#[derive(Debug)]
pub struct BlindKeyPair {
    sk: BlindSecretKey,
    pub pk: BlindPublicKey,
}

/// Pointcheval-Sanders basic blinded message object
#[derive(Debug, Clone)]
pub struct BlindedMessage {}

/// Pointcheval-Sanders basic blinded signature object
#[derive(Debug, Clone)]
pub struct BlindedSignature {}

/// Pointcheval-Sanders blinding factor for a message or signature
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

    /// Randomizes signature in-place
    pub fn randomize(&mut self, _rng: &mut (impl CryptoRng + RngCore)) {
        todo!()
    }
}

#[allow(dead_code)]
impl BlindSecretKey {
    /// Generates a new secret key given a generator. Only used internally.
    fn new(_rng: &mut (impl CryptoRng + RngCore), _length: usize, _g: G1Projective) -> Self {
        todo!();
    }

    /// Extends a secret key to support blind signatures with a specified generator. Only used internally.
    fn from_secret_key(_sk: &SecretKey, _g: G1Projective) -> Self {
        todo!();
    }

    /// Produces a signature on the given message.
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
    /// Generates a new public key from a secret key + generator. Only used internally.
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

    /// Verifies that the given signature is on the message, using the blinding factor.
    pub fn blind_verify(
        &self,
        _msg: &Message,
        _sig: &BlindedSignature,
        _bf: &BlindingFactor,
    ) -> bool {
        todo!();
    }
}

impl BlindKeyPair {
    /// Generates a new keypair for use with blind signatures
    pub fn new(_length: usize, _rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }

    /// Extends the given keypair to support blind signatures
    pub fn from_keypair(_rng: &mut (impl CryptoRng + RngCore), _kp: &KeyPair) -> Self {
        todo!();
    }

    /// Signs a blinded message
    pub fn try_blind_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &BlindedMessage,
    ) -> Result<BlindedSignature, String> {
        self.sk.try_blind_sign(rng, msg)
    }

    /// Verifies that the given signature is on the message, using the blinding factor.
    pub fn blind_verify(
        &self,
        msg: &Message,
        sig: &BlindedSignature,
        bf: &BlindingFactor,
    ) -> bool {
        self.pk.blind_verify(msg, sig, bf)
    }

    /// Signs a message
    pub fn try_sign(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _msg: &Message,
    ) -> Result<Signature, String> {
        // extracts non-blind keypair and signs
        todo!();
    }

    /// Verifies that the signature is valid and is on the message
    pub fn verify(&self, _msg: &Message, _sig: &Signature) -> bool {
        // extracts non-blind keypair and verifies
        todo!();
    }
}
