// Implementation of randomizable multi-message Pointcheval-Sanders signatures over BLS12-381
use crate::{blinded_signatures::*, types::*};
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
    g: G2Affine,
    /// AKA X~
    x: G2Affine,
    /// AKA Y~_1 ... Y~_l
    ys: Vec<G2Affine>,
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
    /// AKA sigma_1
    h: G1Affine,
    /// AKA sigma_2 or H
    h_exp: G1Affine,
}

impl Signature {
    /// Randomizes signature in-place.
    pub fn randomize(&mut self, _rng: &mut (impl CryptoRng + RngCore)) {
        todo!()
    }
}

impl SecretKey {
    /// Constructs a new SecretKey from scratch
    pub fn new(length: usize, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let x = Scalar::random(&mut *rng);
        let ys = iter::repeat_with(|| Scalar::random(&mut *rng))
            .take(length)
            .collect();
        SecretKey { x, ys }
    }

    /// attempts to sign a message. This is not a constant-time implementation.
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
        // this function shouldn't return ID, but we'll check just in case
        let mut h = G1Projective::random(&mut *rng);
        while bool::from(h.is_identity()) {
            h = G1Projective::random(&mut *rng);
        }
        // exp = x + sum( yi * mi )
        let exp = self.x
            + self
                .ys
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<Scalar>();

        Ok(Signature {
            h: G1Affine::from(h),
            h_exp: G1Affine::from(h * exp),
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

        // G1 * Scalar is point multiplication (Yi = g ^ yi)
        let ys = sk.ys.iter().map(|yi| G2Affine::from(g * yi)).collect();

        PublicKey {
            g: G2Affine::from(g),
            x: G2Affine::from(g * sk.x),
            ys,
        }
    }

    pub fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        if bool::from(sig.h.is_identity()) {
            return false;
        }

        // lhs = x + sum( yi ^ mi )
        let lhs = G2Projective::from(self.x)
            + self
                .ys
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<G2Projective>();

        let verify_pairing = pairing(&sig.h, &lhs.into());
        let signature_pairing = pairing(&sig.h_exp, &self.g);

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

    pub fn to_blinded_keypair(&self, rng: &mut (impl CryptoRng + RngCore)) -> BlindKeyPair {
        BlindKeyPair::from_keypair(rng, &self)
    }

    pub fn try_sign(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> Result<Signature, String> {
        self.sk.try_sign(rng, msg)
    }

    pub fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        self.pk.verify(msg, sig)
    }
}
