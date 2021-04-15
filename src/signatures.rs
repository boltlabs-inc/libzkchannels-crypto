// Implementation of randomizable multi-message Pointcheval-Sanders signatures over BLS12-381
use crate::blinded_signatures::*;
use bls12_381 as BLS12;
use ff::Field;
use group::Group;
use rand::CryptoRng;
use rand_core::RngCore;
use std::ops::Index;

/// Pointcheval-Sanders secret key for normal multi-message signing
pub(crate) struct SecretKey {
    x: BLS12::Scalar,
    ys: Vec<BLS12::Scalar>,
}

/// Pointcheval-Sanders public key for normal multi-message verifying
pub struct PublicKey {
    /// AKA g~
    g: BLS12::G2Affine,
    /// AKA X~
    x: BLS12::G2Affine,
    /// AKA Y~_1 ... Y~_l
    ys: Vec<BLS12::G2Affine>,
}

/// Pointcheval-Sanders keypair
pub struct KeyPair {
    sk: SecretKey,
    pub pk: PublicKey,
}

/// Fixed-length message type used in Pointcheval-Sanders schemes
pub struct Message(Vec<BLS12::Scalar>);

/// Pointcheval-Sanders basic signature object
pub struct Signature {
    /// AKA sigma_1
    h: BLS12::G1Affine,
    /// AKA sigma_2 or H
    h_exp: BLS12::G1Affine,
}

impl Index<usize> for Message {
    type Output = BLS12::Scalar;

    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}

impl Message {
    pub fn new(m: Vec<BLS12::Scalar>) -> Self {
        Message(m)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl SecretKey {
    /// Constructs a new SecretKey from scratch
    pub fn new(length: usize, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let x = BLS12::Scalar::random(&mut *rng);
        let mut ys = Vec::with_capacity(length);
        for _i in 0..length {
            ys.push(BLS12::Scalar::random(&mut *rng));
        }
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
        let mut h = BLS12::G1Projective::random(&mut *rng);
        while bool::from(h.is_identity()) {
            h = BLS12::G1Projective::random(&mut *rng);
        }
        let mut exp = self.x;
        for i in 0..msg.len() {
            exp += self.ys[i] * msg[i];
        }

        Ok(Signature {
            h: BLS12::G1Affine::from(h),
            h_exp: BLS12::G1Affine::from(h * exp),
        })
    }
}

impl PublicKey {
    /// Constructs a new PublicKey out of the scalars in SecretKey
    fn from_secret_key(sk: &SecretKey, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        // select g randomly from G*_2
        // this function shouldn't return ID, but we'll check just in case
        let mut g = BLS12::G2Projective::random(&mut *rng);
        while bool::from(g.is_identity()) {
            g = BLS12::G2Projective::random(&mut *rng);
        }

        // G1 * Scalar is point multiplication (Yi = g ^ yi)
        let mut ys = Vec::with_capacity(sk.ys.len());
        for yi in &sk.ys {
            ys.push(BLS12::G2Affine::from(g * yi));
        }

        PublicKey {
            g: BLS12::G2Affine::from(g),
            x: BLS12::G2Affine::from(g * sk.x),
            ys,
        }
    }

    pub fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        if bool::from(sig.h.is_identity()) {
            println!("It's identity!");
            return false;
        }
        let mut lhs = BLS12::G2Projective::from(self.x);
        for i in 0..self.ys.len() {
            lhs += self.ys[i] * msg[i];
        }

        let verify_pairing = BLS12::pairing(&sig.h, &BLS12::G2Affine::from(lhs));
        let signature_pairing = BLS12::pairing(&sig.h_exp, &self.g);

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

    pub fn get_blinded_keypair(&self) -> BlindKeyPair {
        BlindKeyPair::from_secret_key(&self.sk)
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
