/*!
Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381.

More information on the constructs involved can be found in the documentation for the
[`ps_signatures`](crate::ps_signatures) module.
*/
use crate::{
    message::BlindingFactor, pedersen_commitments::*, ps_keys::*, ps_signatures::Signature,
    types::*, Error,
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
        self.0.randomize(rng);
    }

    /**
    Check whether the signature is well-formed.

    This checks that first element is not the identity element. This implementation uses only
    checked APIs to ensure that both parts of the signature are in the expected group (G1).
    */
    pub fn is_well_formed(&self) -> bool {
        self.0.is_well_formed()
    }
}

impl PublicKey {
    /// Blind a message using the given blinding factor.
    pub fn blind_message(
        &self,
        msg: &Message,
        bf: BlindingFactor,
    ) -> Result<BlindedMessage, Error> {
        match self.to_g1_pedersen_parameters().commit(msg, bf) {
            Ok(com) => Ok(BlindedMessage(com)),
            Err(m) => Err(m),
        }
    }
}

impl KeyPair {
    /// Sign a blinded message.
    ///
    /// **Warning**: this should *only* be used if the signer has verified a proof of knowledge of
    /// the opening of the `BlindedMessage`.
    pub fn blind_sign(&self, rng: &mut impl Rng, msg: &BlindedMessage) -> BlindedSignature {
        let u = Scalar::random(rng);

        BlindedSignature(Signature {
            sigma1: (self.public_key().g1 * u).into(),
            sigma2: ((self.secret_key().x1 + msg.0 .0) * u).into(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{ps_signatures::*, types::*};
    use bls12_381::Scalar;
    use ff::Field;
    use std::iter;

    #[test]
    fn blind_signing_verifies() {
        let mut rng = crate::test::rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let bf = BlindingFactor::new(&mut rng);
        let blinded_msg = kp
            .public_key()
            .blind_message(&msg, bf)
            .expect("Impossible: message is the same size as key.");
        let blind_sig = kp.blind_sign(&mut rng, &blinded_msg);
        let sig = blind_sig.unblind(bf);

        assert!(kp.verify(&msg, &sig), "Signature didn't verify!!");
    }

    #[test]
    fn blind_signing_requires_correct_blinding_factor() {
        let mut rng = crate::test::rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let bf = BlindingFactor::new(&mut rng);
        let blinded_msg = kp
            .public_key()
            .blind_message(&msg, bf)
            .expect("Impossible: message is the same size as key.");
        let blind_sig = kp.blind_sign(&mut rng, &blinded_msg);

        let bad_bf = BlindingFactor::new(&mut rng);
        let sig = blind_sig.unblind(bad_bf);

        assert!(
            !kp.verify(&msg, &sig),
            "Signature verified!! (*not* good, *do not* want this)"
        );
    }

    #[test]
    fn blind_signature_randomization_commutes() {
        let mut rng = crate::test::rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let sig = kp.try_sign(&mut rng, &msg).unwrap();
        let bf = BlindingFactor::new(&mut rng);
        let mut blind_sig = BlindedSignature::blind(sig, bf);
        blind_sig.randomize(&mut rng);
        let sig = blind_sig.unblind(bf);

        assert!(kp.verify(&msg, &sig), "Signature didn't verify!!");
    }
}
