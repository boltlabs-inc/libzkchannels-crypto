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
use serde::*;

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

    /// Return the message length that this keypair can operate on.
    pub fn message_len(&self) -> usize {
        self.y1s.len()
    }

    /// Represent the G2 elements of `PublicKey` as [`PedersenParameters`].
    pub fn to_g2_pedersen_parameters(&self) -> PedersenParameters<G2Projective> {
        todo!();
    }

    /// Represent the G1 elements of `PublicKey` as [`PedersenParameters`].
    pub fn to_g1_pedersen_parameters(&self) -> PedersenParameters<G1Projective> {
        todo!();
    }
}

impl KeyPair {
    /// Generate a new random `KeyPair` of a given length..
    pub fn new(_length: usize, _rng: &mut impl Rng) -> Self {
        todo!();
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
