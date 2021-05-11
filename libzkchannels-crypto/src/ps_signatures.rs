//! Implementation of randomizable multi-message Pointcheval-Sanders signatures over BLS12-381.
//!
//! The signature scheme is defined in the 2016 paper, "Short randomizable signatures"
//! available at: https://eprint.iacr.org/2015/525.pdf.
//!
//! The BLS12-381 curve is defined in the (now expired) IRTF draft titled "BLS Signatures",
//! available at: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/.
use crate::{ps_keys::*, types::*};

/// A type that can try to sign a message.
pub trait Signer {
    /// Sign a message.
    fn try_sign(
        &self,
        rng: &mut impl Rng,
        msg: &Message,
    ) -> Result<Signature, String>;
}

/// A type that can verify a signature on a message.
pub trait Verifier {
    /// Verify a signature on a given message.
    fn verify(&self, msg: &Message, sig: &Signature) -> bool;
}

/// A signature on a message, generated using Pointcheval-Sanders.
#[derive(Debug, Clone, Copy)]
pub struct Signature {
    /// AKA h
    sigma1: G1Affine,
    /// AKA H
    sigma2: G1Affine,
}

impl Signature {
    /// Randomizes signature in place.
    pub fn randomize(&mut self, _rng: &mut impl Rng) {
        todo!()
    }
}

impl Signer for SecretKey {
    /// Attempts to sign a message.
    fn try_sign(
        &self,
        _rng: &mut impl Rng,
        _msg: &Message,
    ) -> Result<Signature, String> {
        todo!();
    }
}

impl Verifier for PublicKey {
    /// Verifies that the signature is valid and is on the message.
    fn verify(&self, _msg: &Message, _sig: &Signature) -> bool {
        todo!();
    }
}

impl Signer for KeyPair {
    /// Signs a message.
    fn try_sign(
        &self,
        rng: &mut impl Rng,
        msg: &Message,
    ) -> Result<Signature, String> {
        self.sk.try_sign(rng, msg)
    }
}

impl Verifier for KeyPair {
    /// Verifies that the signature is valid and is on the message.
    fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        self.pk.verify(msg, sig)
    }
}
