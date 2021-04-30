// Implementation of randomizable multi-message Pointcheval-Sanders signatures over BLS12-381
use crate::types::*;
use ff::Field;
use group::Group;
use rand::CryptoRng;
use rand_core::RngCore;
use std::iter;

/// Pointcheval-Sanders secret key for normal multi-message signing
#[derive(Debug)]
pub(crate) struct SecretKey {
    x: Scalar,
    ys: Vec<Scalar>,
}

/// Pointcheval-Sanders public key for normal multi-message verifying
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// AKA g~
    g2: G2Affine,
    /// AKA X~
    x2: G2Affine,
    /// AKA Y~_1 ... Y~_l
    y2s: Vec<G2Affine>,
}

/// Pointcheval-Sanders keypair
#[derive(Debug)]
pub struct KeyPair {
    pub(crate) sk: SecretKey,
    pub pk: PublicKey,
}

/// Pointcheval-Sanders basic signature object
#[derive(Debug, Clone)]
pub struct Signature {
    /// AKA h
    sigma1: G1Affine,
    /// AKA H
    sigma2: G1Affine,
}

impl Signature {
    /// Randomizes signature in-place
    pub fn randomize(&mut self, _rng: &mut (impl CryptoRng + RngCore)) {
        todo!()
    }
}

impl SecretKey {
    /// Constructs a new SecretKey from scratch
    pub fn new(length: usize, rng: &mut (impl CryptoRng + RngCore)) -> Self {
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

    /// Attempts to sign a message. This is not a constant-time implementation.
    pub fn try_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> Result<Signature, String> {
        if self.ys.len() != msg.len() {
            return Err(format!(
                "Message is incorrect length ({}, expected {})",
                msg.len(),
                self.ys.len()
            ));
        }
        // select h randomly from G*_1
        // this function shouldn't return ID but we'll check anyway
        let mut h = G1Projective::random(&mut *rng);
        while bool::from(h.is_identity()) {
            h = G1Projective::random(&mut *rng);
        }

        // [x] + sum( [yi] * [mi] ), for the secret key ([x], [y1], ...) and message [m1] ...
        let scalar_combination = self.x
            + self
                .ys
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<Scalar>();

        Ok(Signature {
            sigma1: h.into(),
            // sigma2 = h * [scalar_combination]
            sigma2: G1Affine::from(h * scalar_combination),
        })
    }
}

impl PublicKey {
    /// Constructs a new PublicKey out of the scalars in SecretKey
    fn from_secret_key(sk: &SecretKey, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        // select g randomly from G*_2
        // this function shouldn't return ID, but we'll check just in case
        let mut g = G2Projective::random(&mut *rng);
        while bool::from(g.is_identity()) {
            g = G2Projective::random(&mut *rng);
        }

        // y2i = g * [yi] (point multiplication with the secret key)
        let ys = sk.ys.iter().map(|yi| G2Affine::from(g * yi)).collect();

        PublicKey {
            g2: G2Affine::from(g),
            // x2 = g * [x]
            x2: G2Affine::from(g * sk.x),
            y2s: ys,
        }
    }

    /// Verifies that the signature is valid and is on the message
    pub fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        if bool::from(sig.sigma1.is_identity()) {
            return false;
        }

        // x + sum( yi * [mi] ), for the public key (x, y1, ...) and message [m1], [m2]...
        let lhs = self.x2
            + self
                .y2s
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<G2Projective>();

        let verify_pairing = pairing(&sig.sigma1, &lhs.into());
        let signature_pairing = pairing(&sig.sigma2, &self.g2);

        verify_pairing == signature_pairing
    }
}

impl KeyPair {
    /// Creates a new KeyPair from scratch
    pub fn new(length: usize, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let sk = SecretKey::new(length, rng);
        let pk = PublicKey::from_secret_key(&sk, rng);
        KeyPair { sk, pk }
    }

    /// Extends keypair to support blinded signatures
    // pub fn to_blinded_keypair(&self, rng: &mut (impl CryptoRng + RngCore)) -> BlindKeyPair {
    //     BlindKeyPair::from_keypair(rng, &self)
    // }

    /// Signs a message
    pub fn try_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> Result<Signature, String> {
        self.sk.try_sign(rng, msg)
    }

    /// Verifies that the signature is valid and is on the message
    pub fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        self.pk.verify(msg, sig)
    }
}
