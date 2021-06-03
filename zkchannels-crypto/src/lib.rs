/*!
This crate includes cryptographic primitives instantiated over the pairing-friendly curve BLS12-381:
- Pedersen Commitments instantiated using G1 and G2.
- Pointcheval Sanders signatures and blind signatures (CT-RSA 2016).
- Schnorr-style zero-knowledge proofs for commitments, signatures, conjunctions, linear relationships, and ranges
*/

#![warn(missing_docs)]
#![warn(missing_copy_implementations, missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(broken_intra_doc_links)]

pub mod challenge;
pub mod commitment_proof;
pub mod message;
pub mod pedersen_commitments;
pub mod ps_blind_signatures;
pub mod ps_keys;
pub mod ps_signatures;
pub mod range_proof;
pub mod signature_proof;

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

mod serde;

pub use crate::{
    serde::{SerializeElement, SerializeG1, SerializeG2},
    types::Rng,
};

mod types {
    pub use crate::message::*;
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
mod test {
    use crate::types::*;
    use rand::SeedableRng;

    pub const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";

    pub fn rng() -> impl Rng {
        rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
    }
}
