//! This defines a class of keys for use across the schemes in this crate.
//!
//! The keys themselves are formed as for blind multi-message Pointcheval-Sanders signatures over
//! BLS12-381. They can also be used for non-blind PS signatures.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable signatures"]
//! (https://eprint.iacr.org/2015/525.pdf).
//!
//! The BLS12-381 curve is defined in the (now expired) IRTF draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

use crate::{common::*, pedersen_commitments::PedersenParameters, SerializeElement};
use arrayvec::ArrayVec;
use ff::Field;
use serde::*;
use std::iter;

/// Pointcheval-Sanders secret key for multi-message operations.
#[derive(Debug)]
pub(crate) struct SecretKey<const N: usize> {
    pub x: Scalar,
    pub ys: [Scalar; N],
    pub x1: G1Affine,
}

/// A public key for multi-message operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey<const N: usize> {
    /// G1 generator (g)
    #[serde(with = "SerializeElement")]
    pub g1: G1Affine,
    /// Y_1 ... Y_l
    #[serde(with = "SerializeElement")]
    pub y1s: [G1Affine; N],
    /// G2 generator (g~)
    #[serde(with = "SerializeElement")]
    pub g2: G2Affine,
    /// X~
    #[serde(with = "SerializeElement")]
    pub x2: G2Affine,
    /// Y~_1 ... Y~_l
    #[serde(with = "SerializeElement")]
    pub y2s: [G2Affine; N],
}

/// A keypair formed from a `SecretKey` and a [`PublicKey`] for multi-message operations.
#[derive(Debug)]
pub struct KeyPair<const N: usize> {
    /// Secret key for multi-message operations.
    sk: SecretKey<N>,
    /// Public key for multi-message operations.
    pk: PublicKey<N>,
}

impl<const N: usize> SecretKey<N> {
    /**
    Generate a new `SecretKey` of a given length, based on [`Scalar`]s chosen uniformly at random
    and the given generator `g1` from G1.

    This is called internally, and we require `g1` is chosen uniformly at random and is not
    the identity element.
    */
    fn new(rng: &mut impl Rng, g1: &G1Projective) -> Self {
        let mut get_nonzero_scalar = || loop {
            let r = Scalar::random(&mut *rng);
            if !r.is_zero() {
                return r;
            }
        };

        let x = get_nonzero_scalar();
        let ys = iter::repeat_with(get_nonzero_scalar)
            .take(N)
            .collect::<ArrayVec<_, N>>()
            .into_inner()
            .unwrap();
        let x1 = (g1 * x).into();
        SecretKey { x, ys, x1 }
    }
}

impl<const N: usize> PublicKey<N> {
    /// Derive a new `PublicKey` from an existing [`SecretKey`] and a generator from G1.
    ///
    /// This is called internally, and we require `g1` is chosen uniformly at random and is not the
    /// identity.
    fn from_secret_key(rng: &mut impl Rng, sk: &SecretKey<N>, g1: &G1Projective) -> Self {
        // select g2 randomly from G2*.
        let g2: G2Projective = random_non_identity(&mut *rng);

        // y1i = g1 * [yi] (point multiplication with the secret key)
        let y1s = sk
            .ys
            .iter()
            .map(|yi| (g1 * yi).into())
            .collect::<ArrayVec<_, N>>()
            .into_inner()
            .expect("lengths guaranteed to match");

        // y2i = g2 * [yi] (point multiplication with the secret key)
        let y2s = sk
            .ys
            .iter()
            .map(|yi| (g2 * yi).into())
            .collect::<ArrayVec<_, N>>()
            .into_inner()
            .expect("lengths guaranteed to match");

        PublicKey {
            g1: g1.into(),
            y1s,
            g2: (g2).into(),
            // x2 = g * [x]
            x2: (g2 * sk.x).into(),
            y2s,
        }
    }

    /// Return the message length that this keypair can operate on.
    pub fn message_len(&self) -> usize {
        self.y1s.len()
    }

    /// Represent the G2 elements of `PublicKey` as [`PedersenParameters`].
    pub fn to_g2_pedersen_parameters(&self) -> PedersenParameters<G2Projective, N> {
        let gs = self
            .y2s
            .iter()
            .map(|y2| y2.into())
            .collect::<ArrayVec<_, N>>()
            .into_inner()
            .expect("lengths guaranteed to match");
        PedersenParameters {
            h: self.g2.into(),
            gs,
        }
    }

    /// Represent the G1 elements of `PublicKey` as [`PedersenParameters`].
    pub fn to_g1_pedersen_parameters(&self) -> PedersenParameters<G1Projective, N> {
        let gs = self
            .y1s
            .iter()
            .map(|y1| y1.into())
            .collect::<ArrayVec<_, N>>()
            .into_inner()
            .expect("lengths guaranteed to match");
        PedersenParameters {
            h: self.g1.into(),
            gs,
        }
    }
}

impl<const N: usize> KeyPair<N> {
    /**
    Generate a new `KeyPair` of a given length.

    Generators are chosen uniformly at random from G1* and G2*. The scalars in the secret key
    are chosen uniformly at random and are non-zero.
    */
    pub fn new(rng: &mut impl Rng) -> Self {
        // select g1 uniformly at random.
        let g1: G1Projective = random_non_identity(&mut *rng);

        // construct keys
        let sk = SecretKey::new(rng, &g1);
        let pk = PublicKey::from_secret_key(rng, &sk, &g1);
        KeyPair { sk, pk }
    }

    /// Get the public portion of the `KeyPair`
    pub fn public_key(&self) -> &PublicKey<N> {
        &self.pk
    }

    /// Get the secret portion of the `KeyPair`
    pub(crate) fn secret_key(&self) -> &SecretKey<N> {
        &self.sk
    }

    /// Return the message length that this keypair can operate on.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        N
    }
}
