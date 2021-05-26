//! Randomizable multi-message Pointcheval-Sanders signatures over BLS12-381.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable signatures"]
//! (https://eprint.iacr.org/2015/525.pdf); The BLS12-381 curve is defined in the (now expired) IRTF
//! draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).
use crate::{ps_keys::*, serde::*, types::*};
use ff::Field;
use group::Group;
use serde::*;

/// A `Signer` may be used to sign a message.
pub trait Signer {
    /// Try to sign a message. Fails if the keypair caller length does not match message length.
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message) -> Result<Signature, String>;
}

/// A `Verifier` may be used to verify a message.
pub trait Verifier {
    /// Verify a signature on a given message.
    fn verify(&self, msg: &Message, sig: &Signature) -> bool;
}

/// A signature on a message, generated using Pointcheval-Sanders.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Signature {
    /**
    First part of a signature.

    In some papers, this is denoted `h`.
    */
    #[serde(with = "SerializeElement")]
    pub(crate) sigma1: G1Affine,
    /**
    Second part of a signature.

    In some papers, this is denoted `H`.
    */
    #[serde(with = "SerializeElement")]
    pub(crate) sigma2: G1Affine,
}

impl Signature {
    /// Randomize a signature in place.
    pub fn randomize(&mut self, rng: &mut impl Rng) {
        let r = Scalar::random(rng);
        *self = Signature {
            sigma1: (self.sigma1 * r).into(),
            sigma2: (self.sigma2 * r).into(),
        };
    }

    /// Convert to a bytewise representation
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut buf: [u8; 96] = [0; 96];
        buf[..48].copy_from_slice(&self.sigma1.to_compressed());
        buf[48..].copy_from_slice(&self.sigma2.to_compressed());
        buf
    }

    /**
    Check whether the signature is well-formed.

    This checks that first element is not the identity element. This implementation uses only
    checked APIs to ensure that both parts of the signature are in the expected group (G1).
    */
    pub fn is_valid(&self) -> bool {
        !bool::from(self.sigma1.is_identity())
    }
}

impl Signer for SecretKey {
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message) -> Result<Signature, String> {
        if self.ys.len() != msg.len() {
            return Err(format!(
                "Message is incorrect length ({}, expected {})",
                msg.len(),
                self.ys.len()
            ));
        }
        // select h randomly from G1*
        // this function shouldn't return ID but we'll check anyway
        let mut h = G1Projective::random(&mut *rng);
        while bool::from(h.is_identity()) {
            h = G1Projective::random(&mut *rng);
        }

        // [x] + sum( [yi] * [mi] ), for the secret key ([x], [y1], ...) and message [m1] ...
        let scalar_combination = self.x
            + self
                .ys
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<Scalar>();

        Ok(Signature {
            sigma1: h.into(),
            // sigma2 = h * [scalar_combination]
            sigma2: (h * scalar_combination).into(),
        })
    }
}

impl Verifier for PublicKey {
    fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        if bool::from(sig.sigma1.is_identity()) {
            return false;
        }

        // x + sum( yi * [mi] ), for the public key (x, y1, ...) and message [m1], [m2]...
        let lhs = self.x2
            + self
                .y2s
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<G2Projective>();

        let verify_pairing = pairing(&sig.sigma1, &lhs.into());
        let signature_pairing = pairing(&sig.sigma2, &self.g2);

        verify_pairing == signature_pairing
    }
}

impl Signer for KeyPair {
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message) -> Result<Signature, String> {
        self.secret_key().try_sign(rng, msg)
    }
}
impl Verifier for KeyPair {
    fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        self.public_key().verify(msg, sig)
    }
}
