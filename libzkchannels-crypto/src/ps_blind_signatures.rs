/*!
Implementation of Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381.

More information on the constructs involved can be found in the documentation for the
[`ps_signatures`](crate::ps_signatures) module.
*/
use crate::{
    pedersen_commitments::PedersenParameters, ps_keys::*, ps_signatures::Signature, types::*,
};

/**
A message, blinded for use in PS blind signature protocols.

Mathematically, this is a commitment produced using the G1 generators of the [`PublicKey`] as
the parameters;
programmatically, a `BlindedMessage` can be constructed using
[`PublicKey::blind_message`].
*/
#[derive(Debug, Clone, Copy)]
pub struct BlindedMessage;

/// A signature on a blinded message, generated using PS blind signing protocols.
///
/// This has the same representation as a regular [`Signature`], but different semantics.
#[derive(Debug, Clone, Copy)]
pub struct BlindedSignature;

/// Pointcheval-Sanders blinding factor for a message or signature.
#[derive(Debug, Clone, Copy)]
pub struct BlindingFactor(pub(crate) Scalar);

impl BlindingFactor {
    /// Generate a new blinding factor uniformly at random from the set of possible [`Scalar`]s.
    pub fn new(_rng: &mut impl Rng) -> Self {
        todo!();
    }
}

impl BlindedSignature {
    /// Blind a [`Signature`] using the given [`BlindingFactor`].
    pub fn from_signature(_sig: &Signature, _bf: &BlindingFactor) -> Self {
        todo!();
    }

    /// Unblind a [`BlindedSignature`]. This will always compute: the user must take care to use
    /// a blinding factor that actually corresponds to the signature in order to retrieve
    /// a valid [`Signature`] on the original message.
    pub fn unblind(&self, _bf: &BlindingFactor) -> Signature {
        todo!()
    }

    /// Randomize a signature in place.
    pub fn randomize(&mut self, _rng: &mut impl Rng) {
        todo!()
    }
}

#[allow(unused)]
impl SecretKey {
    /// Produce a signature on the given message.
    fn try_blind_sign(
        &self,
        _rng: &mut impl Rng,
        _msg: &BlindedMessage,
    ) -> Result<BlindedSignature, String> {
        todo!();
    }
}

impl PublicKey {
    /// Represent the G2 elements of `PublicKey` as [`PedersenParameters`].
    pub fn as_g2_pedersen_parameters(&self) -> PedersenParameters<G2Projective> {
        todo!();
    }

    /// Represent the G1 elements of `PublicKey` as [`PedersenParameters`].
    pub fn as_g1_pedersen_parameters(&self) -> PedersenParameters<G1Projective> {
        todo!();
    }

    /// Blind a message using the given blinding factor.
    pub fn blind_message(_msg: &Message, _bf: &BlindingFactor) -> BlindedMessage {
        todo!();
    }

    /// Verify that the given signature is on the message, using the blinding factor.
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
    /**
    Sign a blinded message.

    Note: this should be used judiciously. The signer should only sign a blinded message if they have great
    confidence that it is something they actually wish to sign. For example, a signer should verify a PoK
    of the opening of the blinded message, which may demonstrate that it satisfies some properties.

    This will fail if the provided [`BlindedMessage`] is not the same length as the `KeyPair`.
    */
    pub fn try_blind_sign(
        &self,
        rng: &mut impl Rng,
        msg: &BlindedMessage,
    ) -> Result<BlindedSignature, String> {
        self.sk.try_blind_sign(rng, msg)
    }

    /// Given the blinding factor, verify that the given signature is valid with respect to the
    /// message, using the blinding factor.
    pub fn verify_blinded(
        &self,
        msg: &Message,
        sig: &BlindedSignature,
        bf: &BlindingFactor,
    ) -> bool {
        self.pk.verify_blinded(msg, sig, bf)
    }
}
