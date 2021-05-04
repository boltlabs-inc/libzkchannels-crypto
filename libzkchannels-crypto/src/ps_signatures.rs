/// Implementation of randomizable multi-message Pointcheval-Sanders signatures over BLS12-381
/// The signature scheme is defined in the 2016 paper, "Short randomizable signatures"
/// Available at: https://eprint.iacr.org/2015/525.pdf
/// The BLS12-381 curve is defined in the (now expired) IRTF draft titled "BLS Signatures",
/// Available at: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/
use crate::{ps_keys::*, types::*};
use group::Group;
use rand::CryptoRng;
use rand_core::RngCore;

/// A type that can try to sign a message
pub trait Signer {
    fn try_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> Result<Signature, String>;
}

/// A type that can verify a signature on a message
pub trait Verifier {
    fn verify(&self, msg: &Message, sig: &Signature) -> bool;
}

/// A signature on a message, generated using Pointcheval-Sanders
#[derive(Debug, Clone)]
pub struct Signature {
    /// AKA h
    sigma1: G1Affine,
    /// AKA H
    sigma2: G1Affine,
}

impl Signature {
    /// Randomizes signature in-place
    pub fn randomize(&mut self, _rng: &mut (impl CryptoRng + RngCore)) {
        todo!()
    }
}

impl Signer for SecretKey {
    /// Attempts to sign a message. This is not a constant-time implementation.
    fn try_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> Result<Signature, String> {
        if self.ys.len() != msg.len() {
            return Err(format!(
                "Message is incorrect length ({}, expected {})",
                msg.len(),
                self.ys.len()
            ));
        }
        // select h randomly from G*_1
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
            sigma2: G1Affine::from(h * scalar_combination),
        })
    }
}

impl Verifier for PublicKey {
    /// Verifies that the signature is valid and is on the message
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
    /// Signs a message
    fn try_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> Result<Signature, String> {
        self.sk.try_sign(rng, msg)
    }
}
impl Verifier for KeyPair {
    /// Verifies that the signature is valid and is on the message
    fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        self.pk.verify(msg, sig)
    }
}
