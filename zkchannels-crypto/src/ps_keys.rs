//! This defines a class of keys for use across the schemes in this crate.
//!
//! The keys themselves are formed as for blind multi-message Pointcheval-Sanders signatures over BLS12-381.
//! They can also be used for non-blind PS signatures.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable signatures"]
//! (https://eprint.iacr.org/2015/525.pdf).
//!
//! The BLS12-381 curve is defined in the (now expired) IRTF
//! draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).
//!

use crate::{pedersen_commitments::PedersenParameters, types::*, SerializeElement};
use ff::Field;
use group::Group;
use serde::*;
use std::iter;

/// Pointcheval-Sanders secret key for multi-message operations.
#[derive(Debug)]
pub(crate) struct SecretKey {
    pub x: Scalar,
    pub ys: Vec<Scalar>,
    pub x1: G1Affine,
}

/// A public key for multi-message operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// G1 generator (g)
    #[serde(with = "SerializeElement")]
    pub g1: G1Affine,
    /// Y_1 ... Y_l
    #[serde(with = "SerializeElement")]
    pub y1s: Vec<G1Affine>,
    /// G2 generator (g~)
    #[serde(with = "SerializeElement")]
    pub g2: G2Affine,
    /// X~
    #[serde(with = "SerializeElement")]
    pub x2: G2Affine,
    /// Y~_1 ... Y~_l
    #[serde(with = "SerializeElement")]
    pub y2s: Vec<G2Affine>,
}

/// A keypair formed from a `SecretKey` and a [`PublicKey`] for multi-message operations.
#[derive(Debug)]
pub struct KeyPair {
    /// Secret key for multi-message operations.
    sk: SecretKey,
    /// Public key for multi-message operations.
    pk: PublicKey,
}

impl SecretKey {
    /// Generate a new `SecretKey` of a given length, based on [`Scalar`]s chosen uniformly at random
    /// and the given generator from G1, which should also be chosen uniformly at random.
    fn new(rng: &mut impl Rng, length: usize, g1: &G1Projective) -> Self {
        let x = SecretKey::get_nonzero_scalar(&mut *rng);
        let ys = iter::repeat_with(|| SecretKey::get_nonzero_scalar(&mut *rng))
            .take(length)
            .collect();
        let x1 = G1Affine::from(g1 * x);
        SecretKey { x, ys, x1 }
    }

    fn get_nonzero_scalar(rng: &mut impl Rng) -> Scalar {
        loop {
            let r = Scalar::random(&mut *rng);
            if !r.is_zero() {
                return r;
            }
        }
    }
}

impl PublicKey {
    /// Derive a new `PublicKey` from an existing [`SecretKey`] and a new generator from G1, chosen uniformly at random.
    fn from_secret_key(rng: &mut impl Rng, sk: &SecretKey, g1: &G1Projective) -> Self {
        // select g2 randomly from G2*
        // this function shouldn't return ID, but we'll check just in case
        let mut g2 = G2Projective::random(&mut *rng);
        while bool::from(g2.is_identity()) {
            g2 = G2Projective::random(&mut *rng);
        }

        // y1i = g1 * [yi] (point multiplication with the secret key)
        let y1s = sk.ys.iter().map(|yi| G1Affine::from(g1 * yi)).collect();

        // y2i = g2 * [yi] (point multiplication with the secret key)
        let y2s = sk.ys.iter().map(|yi| G2Affine::from(g2 * yi)).collect();

        PublicKey {
            g1: g1.into(),
            y1s,
            g2: G2Affine::from(g2),
            // x2 = g * [x]
            x2: G2Affine::from(g2 * sk.x),
            y2s,
        }
    }

    /// Return the message length that this keypair can operate on.
    pub fn message_len(&self) -> usize {
        self.y1s.len()
    }

    /// Represent the G2 elements of `PublicKey` as [`PedersenParameters`].
    pub fn to_g2_pedersen_parameters(&self) -> PedersenParameters<G2Projective> {
        let gs = self.y2s.iter().map(|y2| y2.into()).collect();
        PedersenParameters {
            h: self.g2.into(),
            gs,
        }
    }

    /// Represent the G1 elements of `PublicKey` as [`PedersenParameters`].
    pub fn to_g1_pedersen_parameters(&self) -> PedersenParameters<G1Projective> {
        let gs = self.y1s.iter().map(|y1| y1.into()).collect();
        PedersenParameters {
            h: self.g1.into(),
            gs,
        }
    }
}

impl KeyPair {
    /// Generate a new random `KeyPair` of a given length.
    pub fn new(length: usize, rng: &mut impl Rng) -> Self {
        // select g1 uniformly at random. This shouldn't return ID, but we'll check just in case.
        let mut g1 = G1Projective::random(&mut *rng);
        while bool::from(g1.is_identity()) {
            g1 = G1Projective::random(&mut *rng);
        }

        // construct keys
        let sk = SecretKey::new(rng, length, &g1);
        let pk = PublicKey::from_secret_key(rng, &sk, &g1);
        KeyPair { sk, pk }
    }

    /// Get the public portion of the `KeyPair`
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }

    /// Get the secret portion of the `KeyPair`
    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.sk
    }

    /// Return the message length that this keypair can operate on.
    pub fn message_len(&self) -> usize {
        self.sk.ys.len()
    }
}
