/// Implementation of Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381
/// See references in ps_signatures.rs
use crate::{
    pedersen_commitments::PedersenParameters, ps_keys::*, ps_signatures::Signature, types::*,
};
use rand::CryptoRng;
use rand_core::RngCore;

/// A message, blinded for use in PS blind signature protocols
/// This is a commitment in G1 generated using a BlindPublicKey additional information as generators
#[derive(Debug, Clone)]
pub struct BlindedMessage;

/// A signature on a blinded message, generated using PS blind signing protocols
/// This has the same form as a regular signature
#[derive(Debug, Clone)]
pub struct BlindedSignature;

/// Pointcheval-Sanders blinding factor for a message or signature
#[derive(Debug, Clone, Copy)]
pub struct BlindingFactor(pub Scalar);

impl BlindingFactor {
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}

impl BlindedSignature {
    /// Blinds a signature using the given blinding factor
    pub fn from_signature(_sig: &Signature, _bf: &BlindingFactor) -> Self {
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

#[allow(unused)]
impl SecretKey {
    /// Produces a signature on the given message.
    fn try_blind_sign(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _msg: &BlindedMessage,
    ) -> Result<BlindedSignature, String> {
        todo!();
    }
}

impl PublicKey {
    pub fn as_pedersen_parameters(&self) -> PedersenParameters<G2Projective> {
        todo!();
    }

    /// Blinds a message using the given blinding factor
    pub fn blind_message(_msg: &Message, _bf: &BlindingFactor) -> BlindedMessage {
        todo!();
    }

    /// Verifies that the given signature is on the message, using the blinding factor.
    pub fn verify_blinded(
        &self,
        _msg: &Message,
        _sig: &BlindedSignature,
        _bf: &BlindingFactor,
    ) -> bool {
        todo!();
    }
}

impl KeyPair {
    /// Signs a blinded message
    pub fn try_blind_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &BlindedMessage,
    ) -> Result<BlindedSignature, String> {
        self.sk.try_blind_sign(rng, msg)
    }

    /// Verifies that the given signature is on the message, using the blinding factor.
    pub fn verify_blinded(
        &self,
        msg: &Message,
        sig: &BlindedSignature,
        bf: &BlindingFactor,
    ) -> bool {
        self.pk.verify_blinded(msg, sig, bf)
    }
}
