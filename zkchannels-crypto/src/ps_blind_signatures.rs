/*!
Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381.

More information on the constructs involved can be found in the documentation for the
[`ps_signatures`](crate::ps_signatures) module.
*/
use crate::{
    message::BlindingFactor,
    pedersen_commitments::*,
    ps_keys::*,
    ps_signatures::{Signature, Verifier},
    types::*,
};
use ff::Field;
use serde::*;

/**
A message, blinded for use in PS blind signature protocols.

Mathematically, this is a commitment produced using the G1 generators of the [`PublicKey`] as
the parameters;
programmatically, a `BlindedMessage` can be constructed using
[`PublicKey::blind_message`].
*/
#[derive(Debug, Clone, Copy)]
pub struct BlindedMessage(Commitment<G1Projective>);

/// A signature on a blinded message, generated using PS blind signing protocols.
///
/// This has the same representation as a regular [`Signature`], but different semantics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedSignature(pub(crate) Signature);

impl BlindedSignature {
    /// Convert to a bytewise representation
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }
}

impl BlindedSignature {
    /// Blind a [`Signature`] using the given [`BlindingFactor`].
    pub fn blind(sig: Signature, bf: BlindingFactor) -> Self {
        let Signature { sigma1, sigma2 } = sig;
        Self(Signature {
            sigma1,
            sigma2: (sigma2 + (sigma1 * bf.0)).into(),
        })
    }

    /// Unblind a [`BlindedSignature`]. This will always compute: the user must take care to use
    /// a blinding factor that actually corresponds to the signature in order to retrieve
    /// a valid [`Signature`] on the original message.
    pub fn unblind(self, bf: BlindingFactor) -> Signature {
        let Self(Signature { sigma1, sigma2 }) = self;
        Signature {
            sigma1,
            sigma2: (sigma2 - (sigma1 * bf.0)).into(),
        }
    }

    /// Randomize a signature in place.
    pub fn randomize(&mut self, rng: &mut impl Rng) {
        let Self(Signature { sigma1, sigma2 }) = *self;
        let r = Scalar::random(rng);
        *self = Self(Signature {
            sigma1: (sigma1 * r).into(),
            sigma2: (sigma2 * r).into(),
        });
    }

    /// Check whether the signature is well-formed.
    ///
    /// This checks that first element is not the identity element. This implementation uses only
    /// checked APIs to ensure that both parts of the signature are in the expected group (G1).
    pub fn is_valid(&self) -> bool {
        todo!();
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
    /// Blind a message using the given blinding factor.
    pub fn blind_message(&self, msg: &Message, bf: BlindingFactor) -> BlindedMessage {
        BlindedMessage(self.to_g1_pedersen_parameters().commit(msg, bf))
    }

    /// Verify that the given signature is on the message, using the blinding factor.
    pub fn verify_blinded(
        &self,
        msg: &Message,
        blinded_sig: BlindedSignature,
        bf: BlindingFactor,
    ) -> bool {
        let sig = blinded_sig.unblind(bf);
        self.verify(msg, &sig)
    }
}

impl KeyPair {
    /**
    Sign a blinded message.

    Note: this should be used judiciously. The signer should only sign a blinded message if they have great
    confidence that it is something they actually wish to sign. For example, a signer should verify a PoK
    of the opening of the blinded message, which may demonstrate that it satisfies some properties.
    */
    pub fn try_blind_sign(&self, rng: &mut impl Rng, msg: &BlindedMessage) -> BlindedSignature {
        let u = Scalar::random(rng);

        BlindedSignature(Signature {
            sigma1: (self.public_key().g1 * u).into(),
            sigma2: ((self.secret_key().x1 + msg.0 .0) * u).into(),
        })
    }

    /// Given the blinding factor, verify that the given signature is valid with respect to the
    /// message, using the blinding factor.
    pub fn verify_blinded(&self, msg: &Message, sig: BlindedSignature, bf: BlindingFactor) -> bool {
        self.public_key().verify_blinded(msg, sig, bf)
    }
}
