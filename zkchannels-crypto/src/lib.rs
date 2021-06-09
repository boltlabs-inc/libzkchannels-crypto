//! This crate includes cryptographic primitives instantiated over the pairing-friendly curve
//! BLS12-381:
//! - Pedersen Commitments instantiated using G1 and G2.
//! - Pointcheval Sanders signatures and blind signatures (CT-RSA 2016).
//! - Schnorr-style zero-knowledge proofs for commitments, signatures, conjunctions, linear
//!   relationships, and ranges

#![warn(missing_docs)]
#![warn(missing_copy_implementations, missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(broken_intra_doc_links)]

pub mod pedersen;
pub mod pointcheval_sanders;
pub mod proofs;

mod serde;

pub use crate::serde::{SerializeElement, SerializeG1, SerializeG2};

use crate::common::*;
use ::serde::*;
use ff::Field;
use std::ops::Deref;
use thiserror::*;

/// Error types that may arise from cryptographic operations.
#[derive(Debug, Error, Clone, Copy)]
pub enum Error {
    /// Caused by attempting to construct a range proof on an out-of-range value.
    #[error("tried to build a range proof on a negative value ({0})")]
    OutsideRange(i64),
    /// Caused by attempting to commit to a message with a different length than the provided
    /// parameters expected.
    #[error("expected a message of length {expected}, got {got}")]
    MessageLengthMismatch {
        /// The length of the parameters, and expected length of the message.
        expected: usize,
        /// The actual length of the message.
        got: usize,
    },
}

/// Fixed-length message type used across schemes.
#[derive(Debug, Clone, Copy)]
pub struct Message<const N: usize>([Scalar; N]);

impl<const N: usize> Deref for Message<N> {
    type Target = [Scalar; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> Message<N> {
    /// Create a new message from a Vec<Scalar>.
    pub fn new(scalars: [Scalar; N]) -> Self {
        Message(scalars)
    }
}

impl From<Scalar> for Message<1> {
    fn from(scalar: Scalar) -> Self {
        Self([scalar])
    }
}

/// Blinding factor for a commitment, message, or signature.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindingFactor(#[serde(with = "SerializeElement")] Scalar);

impl BlindingFactor {
    /// Generate a new blinding factor uniformly at random from the set of possible [`Scalar`]s.
    pub fn new(rng: &mut impl Rng) -> Self {
        Self(Scalar::random(rng))
    }

    /// Construct a blinding factor from the scalar representing it.
    ///
    /// **warning:** this should never be used unless unblinding something!
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self(scalar)
    }

    /// Convert to the inner scalar representing this blinding factor.
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }
}

mod common {
    //! Common types used internally.

    pub use crate::{BlindingFactor, Message};
    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
    pub use group::{Group, GroupEncoding};

    /// A trait synonym for a cryptographically secure random number generator. This trait is
    /// blanket-implemented for all valid types and will never need to be implemented by-hand.
    pub trait Rng: rand::CryptoRng + rand::RngCore {}
    impl<T: rand::CryptoRng + rand::RngCore> Rng for T {}

    /// Select a non-identity element from the group uniformly at random.
    pub fn random_non_identity<G>(rng: &mut impl Rng) -> G
    where
        G: Group<Scalar = Scalar>,
    {
        loop {
            let g = G::random(&mut *rng);
            if !bool::from(g.is_identity()) {
                return g;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pointcheval_sanders::*;
    use bls12_381::Scalar;
    use ff::Field;

    #[test]
    fn make_keypair() {
        let mut rng = rand::thread_rng();
        let _kp = KeyPair::<3>::new(&mut rng);
    }

    #[test]
    fn signing_is_correct() {
        let mut rng = rand::thread_rng();
        let kp = KeyPair::<3>::new(&mut rng);
        let msg = Message::new([
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ]);

        let sig = kp.sign(&mut rng, &msg);
        assert!(
            kp.public_key().verify(&msg, &sig),
            "Signature didn't verify!! {:?}, {:?}",
            kp,
            msg
        );
    }

    #[test]
    fn blind_signing_is_correct() {
        let mut rng = rand::thread_rng();
        let kp = KeyPair::<3>::new(&mut rng);
        let msg = Message::new([
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ]);

        let bf = BlindingFactor::new(&mut rng);
        let blinded_msg = kp.public_key().blind_message(&msg, bf);
        let blind_sig = kp.blind_sign(&mut rng, &blinded_msg);
        let sig = blind_sig.unblind(bf);

        assert!(
            kp.public_key().verify(&msg, &sig),
            "Signature didn't verify!!"
        );
    }
}
