/// Implementation of Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381
/// See references in ps_signatures.rs
use crate::{pedersen_commitments::PedersenParameters, ps_signatures::*, types::*};
use rand::CryptoRng;
use rand_core::RngCore;

/// Pointcheval-Sanders secret key for blind multi-message signing
/// Includes scalars [x], [y1], ..., [yl] and G1 element X = [x]g
#[derive(Debug)]
pub(crate) struct BlindSecretKey;

/// Pointcheval-Sanders public key for blind multi-message verifying
/// Includes a basic PS public key in G2: (g~, [x]g~, [y1]g~, ...)
/// and additional information for constructing blind signatures in G1: (g, [y1]g, ..., [yl]g)
#[derive(Debug, Clone)]
pub struct BlindPublicKey;

/// Pointcheval-Sanders keypair for blinded operations
#[derive(Debug)]
pub struct BlindKeyPair {
    sk: BlindSecretKey,
    pub pk: BlindPublicKey,
}

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

#[allow(dead_code)]
impl BlindSecretKey {
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
    pub fn as_pedersen_parameters(&self) -> PedersenParameters<G2Projective> {
        todo!();
    }

    /// Blinds a message using the given blinding factor
    pub fn blind_message(_msg: &Message, _bf: &BlindingFactor) -> BlindedMessage {
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
    pub fn blind_verify(&self, msg: &Message, sig: &BlindedSignature, bf: &BlindingFactor) -> bool {
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
