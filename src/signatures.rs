// Implementation of randomizable multi-message Pointcheval-Sanders signatures over BLS12-381
use crate::blinded_signatures::*;
use bls12_381 as BLS12;
use ff::Field;
use group::Group;
use rand::CryptoRng;
use rand_core::RngCore;

pub(crate) struct SecretKey {
    x: BLS12::Scalar,
    ys: Vec<BLS12::Scalar>,
}

#[allow(dead_code)]
pub struct PublicKey {
    g: BLS12::G2Affine,
    x: BLS12::G2Affine,
    ys: Vec<BLS12::G2Affine>,
}

pub struct KeyPair {
    sk: SecretKey,
    pub pk: PublicKey,
}

pub struct Message {}

pub struct Signature {}

impl SecretKey {
    /// Constructs a new SecretKey from scratch
    pub fn new<R: RngCore>(length: usize, rng: &mut R) -> Self
    where
        R: CryptoRng,
    {
        let x = BLS12::Scalar::random(&mut *rng);
        let mut ys = Vec::with_capacity(length);
        for _i in 0..length {
            ys.push(BLS12::Scalar::random(&mut *rng));
        }
        SecretKey { x, ys }
    }

    pub fn sign(&self, _msg: Message) -> Signature {
        todo!()
    }
}

impl PublicKey {
    /// Constructs a new PublicKey out of the scalars in SecretKey
    fn from_secret_key<R: RngCore>(sk: &SecretKey, rng: &mut R) -> Self
    where
        R: CryptoRng,
    {
        let gen = BLS12::G2Projective::random(rng);

        // G1 * Scalar is point multiplication (Yi = g ^ yi)
        let mut ys = Vec::with_capacity(sk.ys.len());
        for yi in &sk.ys {
            ys.push(BLS12::G2Affine::from(gen * yi));
        }

        PublicKey {
            g: BLS12::G2Affine::from(gen),
            x: BLS12::G2Affine::from(gen * sk.x),
            ys,
        }
    }

    pub fn verify(&self, _sig: Signature) -> bool {
        todo!();
    }
}

impl KeyPair {
    /// Creates a new KeyPair from scratch
    pub fn new<R: RngCore>(length: usize, rng: &mut R) -> Self
    where
        R: CryptoRng,
    {
        let sk = SecretKey::new(length, rng);
        let pk = PublicKey::from_secret_key(&sk, rng);
        KeyPair { sk, pk }
    }

    pub fn get_blinded_keypair(&self) -> BlindKeyPair {
        BlindKeyPair::from_secret_key(&self.sk)
    }

    pub fn sign(&self, msg: Message) -> Signature {
        self.sk.sign(msg)
    }

    pub fn verify(&self, sig: Signature) -> bool {
        self.pk.verify(sig)
    }
}
