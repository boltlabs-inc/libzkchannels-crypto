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
#[macro_use]
mod sqlite;

mod serde;

pub use crate::{
    common::Rng,
    serde::{SerializeElement, SerializeG1, SerializeG2},
};

use crate::common::*;
use ::serde::*;
use arrayvec::ArrayVec;
use ff::Field;
use pedersen::{Commitment, PedersenParameters};
use pointcheval_sanders::{BlindedMessage, KeyPair, PublicKey, Signature};
use std::{iter, ops::Deref};

/// Fixed-length message type used across schemes.
///
/// Uses Box to avoid stack overflows with long messages.
#[derive(Debug, Clone)]
pub struct Message<const N: usize>(Box<[Scalar; N]>);

impl<const N: usize> Deref for Message<N> {
    type Target = [Scalar; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> Message<N> {
    /// Create a new message from an array of scalars.
    pub fn new(scalars: [Scalar; N]) -> Self {
        Message(Box::new(scalars))
    }

    /// Create a new message consisting of random scalars. Useful for testing purposes.
    pub fn random(rng: &mut impl Rng) -> Self {
        Message(Box::new(
            iter::repeat_with(|| Scalar::random(&mut *rng))
                .take(N)
                .collect::<ArrayVec<_, N>>()
                .into_inner()
                .expect("length mismatch impossible"),
        ))
    }

    /// Form a Pedersen commitment to the message using the provided Pedersen parameters and blinding factor.
    pub fn commit<G: Group<Scalar = Scalar>>(
        &self,
        pedersen_params: &PedersenParameters<G, N>,
        bf: BlindingFactor,
    ) -> Commitment<G> {
        Commitment::new(self, pedersen_params, bf)
    }

    /// Form a Pointcheval Sanders blinded message from the message, using the Pointcheval Sanders blind signing public key and blinding factor.
    pub fn blind(&self, public_key: &PublicKey<N>, bf: BlindingFactor) -> BlindedMessage {
        BlindedMessage::new(public_key, self, bf)
    }

    /// Sign a message using Pointcheval Sanders.
    pub fn sign(&self, rng: &mut impl Rng, kp: &KeyPair<N>) -> Signature {
        Signature::new(rng, kp, self)
    }
}

impl From<Scalar> for Message<1> {
    fn from(scalar: Scalar) -> Self {
        Self(Box::new([scalar]))
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
    pub(crate) fn from_scalar(scalar: Scalar) -> Self {
        Self(scalar)
    }

    /// Convert to the inner scalar representing this blinding factor.
    pub fn as_scalar(&self) -> Scalar {
        self.0
    }
}

mod common {
    //! Common types used internally.

    use std::{iter::Sum, ops::Mul};

    pub use crate::{BlindingFactor, Message};
    pub use bls12_381::{
        multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar,
    };
    pub use arrayvec::ArrayVec;
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

    /// Map a function over a fixed-size array.
    pub fn map_array<T, X, F, const N: usize>(ts: &[T; N], f: F) -> [X; N]
    where
        F: Fn(&T) -> X + Sized,
        X: core::fmt::Debug,
    {
        ts.iter()
            .map(f)
            .collect::<ArrayVec<X, N>>()
            .into_inner()
            .expect("lengths guaranteed to match")
    }

    /// Computes the sum of the product of the elements in the two arrays.
    /// In practice, the type T will be either a Group<Scalar = Scalar> or a Scalar.
    pub fn inner_product<'b, T, X, const N: usize>(ts: &'b [T; N], us: &'b [Scalar; N]) -> X
    where
        X: Sum<X> + core::fmt::Debug,
        T: 'b + Mul<&'b Scalar, Output = X> + Copy,
    {
        ts.iter().zip(us.iter()).map(|(&t, u)| t * u).sum::<X>()
    }
}

#[cfg(test)]
mod test {
    use crate::common::*;
    use rand::SeedableRng;

    pub const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";

    pub fn rng() -> impl Rng {
        rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
    }

    #[test]
    fn map_arithmetic_on_array() {
        let arr = [0, 1, 2, 3, 4, 5, 6];
        let double_array = map_array(&arr, |x| x * 2);
        assert_eq!(double_array, [0, 2, 4, 6, 8, 10, 12])
    }

    #[test]
    fn small_inner_product_g1() {
        let units = [G1Projective::identity(); 5];
        let scalars = [
            Scalar::one(),
            Scalar::from(2),
            Scalar::from(3),
            Scalar::from(4),
            Scalar::from(5),
        ];
        let ip = inner_product(&units, &scalars);
        assert_eq!(ip, G1Projective::identity() * Scalar::from(15))
    }

    #[test]
    fn small_inner_product_g2() {
        let units = [G2Projective::identity(); 5];
        let scalars = [
            Scalar::one(),
            Scalar::from(2),
            Scalar::from(3),
            Scalar::from(4),
            Scalar::from(5),
        ];
        let ip = inner_product(&units, &scalars);
        assert_eq!(ip, G2Projective::identity() * Scalar::from(25))
    }
}
