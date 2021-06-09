//! Randomizable multi-message Pointcheval-Sanders signatures, blinded signatures, and keys over
//! BLS12-381.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable signatures"]
//! (https://eprint.iacr.org/2015/525.pdf); The BLS12-381 curve is defined in the (now expired) IRTF
//! draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

use crate::{common::*, pedersen::*, serde::*, BlindingFactor, Error};
use arrayvec::ArrayVec;
use ff::Field;
use serde::*;
use std::iter;

/// A `Signer` may be used to sign a message.
pub trait Signer<const N: usize> {
    /// Try to sign a message. Fails if the keypair caller length does not match message length.
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message<N>) -> Result<Signature, String>;
}

/// A `Verifier` may be used to verify a message.
pub trait Verifier<const N: usize> {
    /// Verify a signature on a given message.
    fn verify(&self, msg: &Message<N>, sig: &Signature) -> bool;
}

/// A signature on a message, generated using Pointcheval-Sanders.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Signature {
    /// First part of a signature.
    ///
    /// In some papers, this is denoted `h`.
    #[serde(with = "SerializeElement")]
    pub(crate) sigma1: G1Affine,
    /// Second part of a signature.
    ///
    /// In some papers, this is denoted `H`.
    #[serde(with = "SerializeElement")]
    pub(crate) sigma2: G1Affine,
}

impl Signature {
    /// Randomize a signature in place.
    pub fn randomize(&mut self, rng: &mut impl Rng) {
        let r = Scalar::random(rng);
        *self = Signature {
            sigma1: (self.sigma1 * r).into(),
            sigma2: (self.sigma2 * r).into(),
        };
    }

    /// Convert to a bytewise representation
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut buf: [u8; 96] = [0; 96];
        buf[..48].copy_from_slice(&self.sigma1.to_compressed());
        buf[48..].copy_from_slice(&self.sigma2.to_compressed());
        buf
    }

    /// Check whether the signature is well-formed.
    ///
    /// This checks that first element is not the identity element. This implementation uses only
    /// checked APIs to ensure that both parts of the signature are in the expected group (G1).
    pub fn is_well_formed(&self) -> bool {
        !bool::from(self.sigma1.is_identity())
    }
}

impl<const N: usize> Signer<N> for SecretKey<N> {
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message<N>) -> Result<Signature, String> {
        if self.ys.len() != msg.len() {
            return Err(format!(
                "Message is incorrect length ({}, expected {})",
                msg.len(),
                self.ys.len()
            ));
        }
        // select h randomly from G1*.
        let h: G1Projective = random_non_identity(&mut *rng);

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
            sigma2: (h * scalar_combination).into(),
        })
    }
}

impl<const N: usize> Verifier<N> for PublicKey<N> {
    fn verify(&self, msg: &Message<N>, sig: &Signature) -> bool {
        if !sig.is_well_formed() {
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

impl<const N: usize> Signer<N> for KeyPair<N> {
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message<N>) -> Result<Signature, String> {
        self.secret_key().try_sign(rng, msg)
    }
}

impl<const N: usize> Verifier<N> for KeyPair<N> {
    fn verify(&self, msg: &Message<N>, sig: &Signature) -> bool {
        self.public_key().verify(msg, sig)
    }
}

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
    /// Generate a new `SecretKey` of a given length, based on [`Scalar`]s chosen uniformly at random
    /// and the given generator `g1` from G1.

    /// This is called internally, and we require `g1` is chosen uniformly at random and is not
    /// the identity element.
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
    /// Generate a new `KeyPair` of a given length.
    ///
    /// Generators are chosen uniformly at random from G1* and G2*. The scalars in the secret key
    /// are chosen uniformly at random and are non-zero.
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
}

/// A message, blinded for use in PS blind signature protocols.
///
/// Mathematically, this is a commitment produced using the G1 generators of the [`PublicKey`] as
/// the parameters;
/// programmatically, a `BlindedMessage` can be constructed using
/// [`PublicKey::blind_message`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedMessage(Commitment<G1Projective>);

/// A signature on a blinded message, generated using PS blind signing protocols.
///
/// This has the same representation as a regular [`Signature`], but different semantics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedSignature(pub(crate) Signature);

impl BlindedSignature {
    /// Convert to a bytewise representation
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }
}

impl BlindedSignature {
    /// Blind a [`Signature`] using the given [`BlindingFactor`].
    pub fn blind(sig: Signature, bf: BlindingFactor) -> Self {
        let Signature { sigma1, sigma2 } = sig;
        Self(Signature {
            sigma1,
            sigma2: (sigma2 + (sigma1 * bf.0)).into(),
        })
    }

    /// Unblind a [`BlindedSignature`]. This will always compute: the user must take care to use
    /// a blinding factor that actually corresponds to the signature in order to retrieve
    /// a valid [`Signature`] on the original message.
    pub fn unblind(self, bf: BlindingFactor) -> Signature {
        let Self(Signature { sigma1, sigma2 }) = self;
        Signature {
            sigma1,
            sigma2: (sigma2 - (sigma1 * bf.0)).into(),
        }
    }

    /// Randomize a signature in place.
    pub fn randomize(&mut self, rng: &mut impl Rng) {
        self.0.randomize(rng);
    }

    /// Check whether the signature is well-formed.
    ///
    /// This checks that first element is not the identity element. This implementation uses only
    /// checked APIs to ensure that both parts of the signature are in the expected group (G1).
    pub fn is_well_formed(&self) -> bool {
        self.0.is_well_formed()
    }
}

impl<const N: usize> PublicKey<N> {
    /// Blind a message using the given blinding factor.
    pub fn blind_message(
        &self,
        msg: &Message<N>,
        bf: BlindingFactor,
    ) -> Result<BlindedMessage, Error> {
        match self.to_g1_pedersen_parameters().commit(msg, bf) {
            Ok(com) => Ok(BlindedMessage(com)),
            Err(m) => Err(m),
        }
    }
}

impl<const N: usize> KeyPair<N> {
    /// Sign a blinded message.
    ///
    /// **Warning**: this should *only* be used if the signer has verified a proof of knowledge of
    /// the opening of the `BlindedMessage`.
    pub fn blind_sign(&self, rng: &mut impl Rng, msg: &BlindedMessage) -> BlindedSignature {
        let u = Scalar::random(rng);

        BlindedSignature(Signature {
            sigma1: (self.public_key().g1 * u).into(),
            sigma2: ((self.secret_key().x1 + msg.0 .0) * u).into(),
        })
    }
}
