//! Randomizable multi-message Pointcheval-Sanders signatures over BLS12-381.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable signatures"]
//! (https://eprint.iacr.org/2015/525.pdf); The BLS12-381 curve is defined in the (now expired) IRTF
//! draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).
use crate::{ps_keys::*, types::*};

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
#[derive(Debug, Clone, Copy)]
pub struct Signature {
    /**
    First part of a signature.

    In some papers, this is denoted `h`.
    */
    pub(crate) sigma1: G1Affine,
    /**
    Second part of a signature.

    In some papers, this is denoted `H`.
    */
    pub(crate) sigma2: G1Affine,
}

impl Signature {
    /// Randomize a signature in place.
    pub fn randomize(&mut self, _rng: &mut impl Rng) {
        todo!()
    }

    /// Convert to a bytewise representation
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut buf: [u8; 96] = [0; 96];
        buf[..48].copy_from_slice(&self.sigma1.to_compressed());
        buf[48..].copy_from_slice(&self.sigma2.to_compressed());
        buf
    }

    /// Check whether the signature is well-formed:
    /// - The first element is not the identity element;
    /// - Both elements are on the expected curve.
    pub fn is_valid(&self) -> bool {
        todo!();
    }
}

impl Signer for SecretKey {
    fn try_sign(&self, _rng: &mut impl Rng, _msg: &Message) -> Result<Signature, String> {
        todo!();
    }
}

impl Verifier for PublicKey {
    fn verify(&self, _msg: &Message, _sig: &Signature) -> bool {
        todo!();
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
