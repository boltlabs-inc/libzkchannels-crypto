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

use crate::types::*;

/// Pointcheval-Sanders secret key for multi-message operations.
#[derive(Debug)]
pub(crate) struct SecretKey {
    pub x: Scalar,
    pub ys: Vec<Scalar>,
    pub x1: G1Affine,
}

/// Pointcheval-Sanders public key for multi-message operations.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// G1 generator (g)
    pub g1: G1Affine,
    /// Y_1 ... Y_l
    pub y1s: Vec<G1Affine>,
    /// G2 generator (g~)
    pub g2: G2Affine,
    /// X~
    pub x2: G2Affine,
    /// Y~_1 ... Y~_l
    pub y2s: Vec<G2Affine>,
}

/// A keypair formed from a `SecretKey` and a [`PublicKey`].
#[derive(Debug)]
pub struct KeyPair {
    /// Pointcheval-Sanders secret key.
    pub(crate) sk: SecretKey,
    /// Pointcheval-Sanders public key.
    pub pk: PublicKey,
}

#[allow(unused)]
impl SecretKey {
    /// Generate a new `SecretKey` of a given length, based on [`Scalar`]s chosen uniformly at random
    /// and the given generator from G1, which should also be chosen uniformly at random.
    fn new(_rng: &mut impl Rng, _length: usize, _g1: &G1Projective) -> Self {
        todo!();
    }
}

#[allow(unused)]
impl PublicKey {
    /// Derive a new `PublicKey` from an existing [`SecretKey`] and a new generator from G1, chosen uniformly at random.
    fn from_secret_key(_rng: &mut impl Rng, _sk: &SecretKey, _g1: &G1Projective) -> Self {
        todo!();
    }
}

impl KeyPair {
    /// Generate a new random `KeyPair` of a given length..
    pub fn new(_length: usize, _rng: &mut impl Rng) -> Self {
        todo!();
    }
}
