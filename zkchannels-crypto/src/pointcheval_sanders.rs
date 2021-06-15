//! Randomizable multi-message Pointcheval-Sanders signatures, blinded signatures, and keys over
//! BLS12-381.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable
//! signatures"](https://eprint.iacr.org/2015/525.pdf); The BLS12-381 curve is defined in the (now
//! expired) IRTF draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

use crate::{
    common::*,
    pedersen::{Commitment, PedersenParameters},
    proofs::{ChallengeBuilder, ChallengeDigest},
    serde::SerializeElement,
    BlindingFactor,
};
use arrayvec::ArrayVec;
use ff::Field;
use serde::*;
use std::iter;

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
    /// Generate a new `SecretKey` of a given length, based on [`Scalar`]s chosen uniformly at
    /// random and the given generator `g1` from G1. This is called internally, and we require `g1`
    /// is chosen uniformly at random and is not the identity element.
    fn new(rng: &mut impl Rng, g1: &G1Projective) -> Self {
        assert!(
            !bool::from(g1.is_identity()),
            "g1 must not be the identity element"
        );

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

    pub fn sign(&self, rng: &mut impl Rng, msg: &Message<N>) -> Signature {
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

        Signature {
            sigma1: h.into(),
            // sigma2 = h * [scalar_combination]
            sigma2: (h * scalar_combination).into(),
        }
    }
}

impl<const N: usize> PublicKey<N> {
    /// Derive a new `PublicKey` from an existing [`SecretKey`] and a generator from G1.
    ///
    /// This is called internally, and we require `g1` is chosen uniformly at random and is not the
    /// identity.
    fn from_secret_key(rng: &mut impl Rng, sk: &SecretKey<N>, g1: &G1Projective) -> Self {
        assert!(
            !bool::from(g1.is_identity()),
            "g1 must not be the identity element"
        );

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
    pub(crate) fn to_g2_pedersen_parameters(&self) -> PedersenParameters<G2Projective, N> {
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

    /// Verify a signature on a given message.
    pub fn verify(&self, msg: &Message<N>, sig: &Signature) -> bool {
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

    /// Blind a message using the given blinding factor.
    pub fn blind_message(&self, msg: &Message<N>, bf: BlindingFactor) -> BlindedMessage {
        BlindedMessage(self.to_g1_pedersen_parameters().commit(msg, bf))
    }
}

impl<const N: usize> ChallengeDigest for PublicKey<N> {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.g1.to_bytes());
        builder.digest_bytes(self.g2.to_bytes());
        builder.digest_bytes(self.x2.to_bytes());

        for y1 in &self.y1s {
            builder.digest_bytes(y1.to_bytes());
        }

        for y2 in &self.y2s {
            builder.digest_bytes(y2.to_bytes());
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

    /// Sign a message.
    pub fn sign(&self, rng: &mut impl Rng, msg: &Message<N>) -> Signature {
        self.sk.sign(rng, msg)
    }

    /// Sign a blinded message.
    ///
    /// **Warning**: this should *only* be used if the signer has verified a proof of knowledge of
    /// the opening of the `BlindedMessage`.
    pub fn blind_sign(&self, rng: &mut impl Rng, msg: &BlindedMessage) -> BlindedSignature {
        let u = Scalar::random(rng);

        BlindedSignature(Signature {
            sigma1: (self.public_key().g1 * u).into(),
            sigma2: ((self.sk.x1 + msg.to_g1()) * u).into(),
        })
    }
}

/// A signature on a message, generated using Pointcheval-Sanders.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Signature {
    /// First part of a signature.
    ///
    /// In some papers, this is denoted `h`.
    #[serde(with = "SerializeElement")]
    sigma1: G1Affine,
    /// Second part of a signature.
    ///
    /// In some papers, this is denoted `H`.
    #[serde(with = "SerializeElement")]
    sigma2: G1Affine,
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

    /// Extract the sigma_1 or `h` component.
    pub fn sigma1(self) -> G1Affine {
        self.sigma1
    }

    /// Extract the sigma_2 or `H` component.
    pub fn sigma2(self) -> G1Affine {
        self.sigma2
    }
}

impl ChallengeDigest for Signature {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.sigma1);
        builder.digest(&self.sigma2);
    }
}

/// A message, blinded for use in PS blind signature protocols.
///
/// Mathematically, this is a commitment produced using the G1 generators of the [`PublicKey`] as
/// the parameters;
/// programmatically, a `BlindedMessage` can be constructed using
/// [`PublicKey::blind_message`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedMessage(pub(crate) Commitment<G1Projective>);

impl BlindedMessage {
    /// Extract the internal commitment object.
    pub fn to_commitment(self) -> Commitment<G1Projective> {
        self.0
    }

    /// Extract the group element corresponding to the internal commitment object. This is shorthand
    /// for `self.to_commitment().to_element()`.
    pub fn to_g1(self) -> G1Projective {
        self.to_commitment().to_element()
    }
}

impl ChallengeDigest for BlindedMessage {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.0);
    }
}

/// A signature on a blinded message, generated using PS blind signing protocols.
///
/// This has the same representation as a regular [`Signature`], but different semantics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedSignature(pub(crate) Signature);

impl BlindedSignature {
    /// Blind a [`Signature`] using the given [`BlindingFactor`].
    pub fn blind(sig: Signature, bf: BlindingFactor) -> Self {
        let Signature { sigma1, sigma2 } = sig;
        Self(Signature {
            sigma1,
            sigma2: (sigma2 + (sigma1 * bf.to_scalar())).into(),
        })
    }

    /// Unblind a [`BlindedSignature`]. This will always compute: the user must take care to use
    /// a blinding factor that actually corresponds to the signature in order to retrieve
    /// a valid [`Signature`] on the original message.
    pub fn unblind(self, bf: BlindingFactor) -> Signature {
        let Self(Signature { sigma1, sigma2 }) = self;
        Signature {
            sigma1,
            sigma2: (sigma2 - (sigma1 * bf.to_scalar())).into(),
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

    /// Convert to a bytewise representation.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }
}

impl ChallengeDigest for BlindedSignature {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.0);
    }
}
