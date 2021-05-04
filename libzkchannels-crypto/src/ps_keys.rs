/// Implementation of keys for basic and blind multi-message Pointcheval-Sanders signatures over BLS12-381
/// The signature scheme is defined in the 2016 paper, "Short randomizable signatures"
/// Available at: https://eprint.iacr.org/2015/525.pdf
/// The BLS12-381 curve is defined in the (now expired) IRTF draft titled "BLS Signatures",
/// Available at: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/
///
/// Note: this currently only implements the basic signature scheme, but will be extended
/// to support blind signatures as well
use crate::types::*;
use ff::Field;
use group::Group;
use rand::CryptoRng;
use rand_core::RngCore;
use std::iter;

/// Pointcheval-Sanders secret key for multi-message signing operations
#[derive(Debug)]
pub(crate) struct SecretKey {
    pub x: Scalar,
    pub ys: Vec<Scalar>,
}

/// Pointcheval-Sanders public key for multi-message operations
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// G2 generator (g~)
    pub g2: G2Affine,
    /// X~
    pub x2: G2Affine,
    /// Y~_1 ... Y~_l
    pub y2s: Vec<G2Affine>,
}

/// Pointcheval-Sanders keypair
#[derive(Debug)]
pub struct KeyPair {
    pub(crate) sk: SecretKey,
    pub pk: PublicKey,
}

impl SecretKey {
    /// Constructs a new SecretKey of the given length
    fn new(rng: &mut (impl CryptoRng + RngCore), length: usize, _g1: &G1Projective) -> Self {
        let x = SecretKey::get_nonzero_scalar(&mut *rng);
        let ys = iter::repeat_with(|| SecretKey::get_nonzero_scalar(&mut *rng))
            .take(length)
            .collect();
        SecretKey { x, ys }
    }

    fn get_nonzero_scalar(rng: &mut (impl CryptoRng + RngCore)) -> Scalar {
        loop {
            let r = Scalar::random(&mut *rng);
            if !r.is_zero() {
                return r;
            }
        }
    }
}

impl PublicKey {
    /// Constructs a new PublicKey out of the scalars in SecretKey
    fn from_secret_key(
        rng: &mut (impl CryptoRng + RngCore),
        sk: &SecretKey,
        _g1: &G1Projective,
    ) -> Self {
        // select g randomly from G2*
        // this function shouldn't return ID, but we'll check just in case
        let mut g2 = G2Projective::random(&mut *rng);
        while bool::from(g2.is_identity()) {
            g2 = G2Projective::random(&mut *rng);
        }

        // y2i = g * [yi] (point multiplication with the secret key)
        let y2s = sk.ys.iter().map(|yi| G2Affine::from(g2 * yi)).collect();

        PublicKey {
            g2: G2Affine::from(g2),
            // x2 = g * [x]
            x2: G2Affine::from(g2 * sk.x),
            y2s,
        }
    }
}

impl KeyPair {
    /// Creates a new KeyPair for multi-message Pointcheval Sanders
    pub fn new(length: usize, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let g1 = G1Projective::random(&mut *rng);
        let sk = SecretKey::new(rng, length, &g1);
        let pk = PublicKey::from_secret_key(rng, &sk, &g1);
        KeyPair { sk, pk }
    }
}
