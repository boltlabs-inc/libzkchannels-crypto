//! Defines a class of keys for use across the schemes in this crate.
//!
//! The keys themselves are formed as for blind multi-message Pointcheval-Sanders signatures over BLS12-381.
//! They can also be used for non-blind PS signatures and as commitment parameters.
//!
//! The signature scheme is defined in the 2016 paper, "Short randomizable signatures".
//! Available at: https://eprint.iacr.org/2015/525.pdf.
//!
//! The BLS12-381 curve is defined in the (now expired) IRTF draft titled "BLS Signatures",
//! Available at: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/.
use crate::types::*;
use rand::CryptoRng;
use rand_core::RngCore;

/// Pointcheval-Sanders secret key for multi-message signing operations.
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

/// Pointcheval-Sanders keypair.
#[derive(Debug)]
pub struct KeyPair {
    pub(crate) sk: SecretKey,
    pub pk: PublicKey,
}

#[allow(unused)]
impl SecretKey {
    /// Constructs a new SecretKey of the given length.
    fn new(_rng: &mut (impl CryptoRng + RngCore), _length: usize, _g1: &G1Projective) -> Self {
        todo!();
    }
}

#[allow(unused)]
impl PublicKey {
    /// Constructs a new PublicKey out of the scalars in SecretKey.
    fn from_secret_key(
        _rng: &mut (impl CryptoRng + RngCore),
        _sk: &SecretKey,
        _g1: &G1Projective,
    ) -> Self {
        todo!();
    }
}

impl KeyPair {
    /// Creates a new KeyPair for multi-message Pointcheval Sanders.
    pub fn new(_length: usize, _rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}
