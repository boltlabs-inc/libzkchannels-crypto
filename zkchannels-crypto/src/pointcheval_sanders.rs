//! Randomizable multi-message Pointcheval-Sanders signatures, blinded signatures, and keys over
//! BLS12-381.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable
//! signatures"](https://eprint.iacr.org/2015/525.pdf); The BLS12-381 curve is defined in the (now
//! expired) IRTF draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

use crate::{
    common::*,
    pedersen::{Commitment, PedersenParameters, ToPedersenParameters},
    proofs::{ChallengeBuilder, ChallengeInput},
    serde::SerializeElement,
    BlindingFactor,
};
use arrayvec::ArrayVec;
use ff::Field;
use group::Curve;
use serde::*;
use std::convert::TryFrom;
use std::{iter, ops::Neg};

/// Pointcheval-Sanders secret key for multi-message operations.
///
/// Uses Box to avoid stack overflows with large keys.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedSecretKey<N>")]
pub(crate) struct SecretKey<const N: usize> {
    #[serde(with = "SerializeElement")]
    x: Scalar,
    #[serde(with = "SerializeElement")]
    ys: Box<[Scalar; N]>,
    #[serde(with = "SerializeElement")]
    x1: G1Affine,
}

/// Pointcheval-Sanders secret key before validation.
///
/// Used during deserialization before validation checks have been done.
#[derive(Debug, Deserialize)]
struct UncheckedSecretKey<const N: usize> {
    #[serde(with = "SerializeElement")]
    x: Scalar,
    #[serde(with = "SerializeElement")]
    ys: Box<[Scalar; N]>,
    #[serde(with = "SerializeElement")]
    x1: G1Affine,
}

impl<const N: usize> TryFrom<UncheckedSecretKey<N>> for SecretKey<N> {
    type Error = String;
    /// During deserialization verify none of the scalars of the secret key are zero, nor is the x1 element the identity element
    fn try_from(unchecked: UncheckedSecretKey<N>) -> Result<Self, Self::Error> {
        let UncheckedSecretKey { x, ys, x1 } = unchecked;

        if x.is_zero() || bool::from(x1.is_identity()) {
            return Err(
                "The secret key must not contain zero scalars nor the identity element".to_string(),
            );
        }
        for y in ys.iter() {
            if y.is_zero() {
                return Err("The secret key must not contain zero scalars".to_string());
            }
        }

        Ok(SecretKey { x, ys, x1 })
    }
}

/// A public key for multi-message operations.
///
/// Uses Box to avoid stack overflows with large keys.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedPublicKey<N>")]
pub struct PublicKey<const N: usize> {
    /// G1 generator (g)
    #[serde(with = "SerializeElement")]
    g1: G1Affine,
    /// Y_1 ... Y_l
    #[serde(with = "SerializeElement")]
    y1s: Box<[G1Affine; N]>,
    /// G2 generator (g~)
    #[serde(with = "SerializeElement")]
    g2: G2Affine,
    /// X~
    #[serde(with = "SerializeElement")]
    x2: G2Affine,
    /// Y~_1 ... Y~_l
    #[serde(with = "SerializeElement")]
    y2s: Box<[G2Affine; N]>,
}

/// Pointcheval-Sanders public key before validation.
///
/// Used during deserialization before validation checks have been done.
#[derive(Debug, Deserialize)]
struct UncheckedPublicKey<const N: usize> {
    /// G1 generator (g)
    #[serde(with = "SerializeElement")]
    g1: G1Affine,
    /// Y_1 ... Y_l
    #[serde(with = "SerializeElement")]
    y1s: Box<[G1Affine; N]>,
    /// G2 generator (g~)
    #[serde(with = "SerializeElement")]
    g2: G2Affine,
    /// X~
    #[serde(with = "SerializeElement")]
    x2: G2Affine,
    /// Y~_1 ... Y~_l
    #[serde(with = "SerializeElement")]
    y2s: Box<[G2Affine; N]>,
}

impl<const N: usize> TryFrom<UncheckedPublicKey<N>> for PublicKey<N> {
    type Error = String;
    /// During deserialization verify none of the elements of the public key are the identity element
    fn try_from(unchecked: UncheckedPublicKey<N>) -> Result<Self, Self::Error> {
        let UncheckedPublicKey {
            g1,
            y1s,
            g2,
            x2,
            y2s,
        } = unchecked;

        if bool::from(g1.is_identity())
            || bool::from(g2.is_identity())
            || bool::from(x2.is_identity())
        {
            return Err(
                "The elements of the public key must not be the identity element".to_string(),
            );
        }
        for (y1, y2) in y1s.iter().zip(y2s.iter()) {
            if bool::from(y1.is_identity()) || bool::from(y2.is_identity()) {
                return Err(
                    "The elements of the public key must not be the identity element".to_string(),
                );
            }
        }

        Ok(PublicKey {
            g1,
            y1s,
            g2,
            x2,
            y2s,
        })
    }
}

/// A keypair formed from a `SecretKey` and a [`PublicKey`] for multi-message operations.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyPair<const N: usize> {
    /// Secret key for multi-message operations.
    sk: SecretKey<N>,
    /// Public key for multi-message operations.
    pk: PublicKey<N>,
}

#[cfg(feature = "sqlite")]
crate::impl_sqlx_for_bincode_ty!(KeyPair<5>);

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
        SecretKey {
            x,
            ys: Box::new(ys),
            x1,
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
        let y1s = map_array(sk.ys.as_ref(), |yi| (g1 * yi).into());

        // y2i = g2 * [yi] (point multiplication with the secret key)
        let y2s = map_array(sk.ys.as_ref(), |yi| (g2 * yi).into());

        PublicKey {
            g1: g1.into(),
            y1s: Box::new(y1s),
            g2: (g2).into(),
            // x2 = g * [x]
            x2: (g2 * sk.x).into(),
            y2s: Box::new(y2s),
        }
    }

    /// Convert the public key to a byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.g1.to_bytes().as_ref());
        for y1 in &*self.y1s {
            buf.extend_from_slice(y1.to_bytes().as_ref());
        }
        buf.extend_from_slice(self.g2.to_bytes().as_ref());
        buf.extend_from_slice(self.x2.to_bytes().as_ref());
        for y2 in &*self.y2s {
            buf.extend_from_slice(y2.to_bytes().as_ref());
        }
        buf
    }

    /// Get the x2 element of the public key
    pub fn x2(&self) -> G2Affine {
        self.x2
    }

    /// Get the y2 elements of the public key
    pub fn y2s(&self) -> Box<[G2Affine; N]> {
        self.y2s.clone()
    }

    /// Get the g2 element of the public key
    pub fn g2(&self) -> G2Affine {
        self.g2
    }
}

impl<const N: usize> ChallengeInput for PublicKey<N> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.g1.to_bytes());
        builder.consume_bytes(self.g2.to_bytes());
        builder.consume_bytes(self.x2.to_bytes());

        for y1 in &*self.y1s {
            builder.consume_bytes(y1.to_bytes());
        }

        for y2 in &*self.y2s {
            builder.consume_bytes(y2.to_bytes());
        }
    }
}

impl<const N: usize> ToPedersenParameters<G1Projective, N> for PublicKey<N> {
    fn to_pedersen_parameters(&self) -> PedersenParameters<G1Projective, N> {
        PedersenParameters::from_generators(
            self.g1.into(),
            map_array(self.y1s.as_ref(), |y1| y1.into()),
        )
    }
}

impl<const N: usize> ToPedersenParameters<G2Projective, N> for PublicKey<N> {
    fn to_pedersen_parameters(&self) -> PedersenParameters<G2Projective, N> {
        PedersenParameters::from_generators(
            self.g2.into(),
            map_array(self.y2s.as_ref(), |y2| y2.into()),
        )
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
}

/// A signature on a message, generated using Pointcheval-Sanders.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedSignature")]
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

/// Pointcheval-Sanders signature before validation.
///
/// Used during deserialization before validation checks have been done.
#[derive(Debug, Deserialize)]
struct UncheckedSignature {
    #[serde(with = "SerializeElement")]
    sigma1: G1Affine,
    #[serde(with = "SerializeElement")]
    sigma2: G1Affine,
}

impl TryFrom<UncheckedSignature> for Signature {
    type Error = String;
    /// During deserialization verify that the first element of the signature is not the identity element
    fn try_from(unchecked: UncheckedSignature) -> Result<Self, Self::Error> {
        let UncheckedSignature { sigma1, sigma2 } = unchecked;

        if bool::from(sigma1.is_identity()) {
            return Err(
                "The first element of a signature must not be the identity element".to_string(),
            );
        }

        Ok(Signature { sigma1, sigma2 })
    }
}

impl Signature {
    pub(crate) fn new<const N: usize>(
        rng: &mut impl Rng,
        signing_keypair: &KeyPair<N>,
        msg: &Message<N>,
    ) -> Self {
        // select h randomly from G1*.
        let h: G1Projective = random_non_identity(&mut *rng);

        // [x] + sum( [yi] * [mi] ), for the secret key ([x], [y1], ...) and message [m1] ...
        let scalar_combination =
            signing_keypair.sk.x + inner_product(signing_keypair.sk.ys.as_ref(), msg);

        Signature {
            sigma1: h.into(),
            // sigma2 = h * [scalar_combination]
            sigma2: (h * scalar_combination).into(),
        }
    }

    /// Randomize a signature in place.
    pub fn randomize(&mut self, rng: &mut impl Rng) {
        let r = Scalar::random(rng);
        *self = Signature {
            sigma1: (self.sigma1 * r).into(),
            sigma2: (self.sigma2 * r).into(),
        };
    }

    /// Blind and Randomize a [`Signature`] using the given [`BlindingFactor`].
    pub fn blind_and_randomize(self, rng: &mut impl Rng, bf: BlindingFactor) -> BlindedSignature {
        let Signature { sigma1, sigma2 } = self;
        let mut blinded_signature = Signature {
            sigma1,
            sigma2: (sigma2 + (sigma1 * bf.as_scalar())).into(),
        };
        blinded_signature.randomize(rng);
        BlindedSignature(blinded_signature)
    }

    /// Convert to a bytewise representation
    pub fn as_bytes(&self) -> [u8; 96] {
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

    /// Verify a signature on a message with respect to a given public key.
    pub fn verify<const N: usize>(&self, public_key: &PublicKey<N>, msg: &Message<N>) -> bool {
        if !self.is_well_formed() {
            return false;
        }

        // x + sum( yi * [mi] ), for the public key (x, y1, ...) and message [m1], [m2]...
        let intermediate = public_key.x2
            + public_key
                .y2s
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<G2Projective>();

        multi_miller_loop(&[
            (&self.sigma1, &intermediate.to_affine().into()),
            (&self.sigma2, &public_key.g2.neg().into()),
        ])
        .final_exponentiation()
            == Gt::identity()
    }
}

impl ChallengeInput for Signature {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.sigma1);
        builder.consume(&self.sigma2);
    }
}

/// A message, blinded for use in PS blind signature protocols.
///
/// Mathematically, this is a commitment produced using the G1 generators of the [`PublicKey`] as
/// the parameters;
/// programmatically, a `BlindedMessage` can be constructed using
/// [`Message::blind()`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedMessage(Commitment<G1Projective>);

impl BlindedMessage {
    pub(crate) fn new<const N: usize>(
        public_key: &PublicKey<N>,
        msg: &Message<N>,
        bf: BlindingFactor,
    ) -> Self {
        let pedersen_params = public_key.to_pedersen_parameters();
        BlindedMessage(msg.commit(&pedersen_params, bf))
    }
}

/// A `VerifiedBlindedMessage` is a `BlindedMessage` for which a prover has provided a
/// [`SignatureRequestProof`](crate::proofs::SignatureRequestProof) that verifies.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct VerifiedBlindedMessage(pub(crate) Commitment<G1Projective>);

impl VerifiedBlindedMessage {
    /// Blind-sign a verified blinded message.
    pub fn blind_sign<const N: usize>(
        self,
        signing_keypair: &KeyPair<N>,
        rng: &mut impl Rng,
    ) -> BlindedSignature {
        BlindedSignature::new(signing_keypair, rng, self)
    }

    /// Extract the internal commitment object.
    pub(crate) fn into_commitment(self) -> Commitment<G1Projective> {
        self.0
    }

    /// Extract the group element corresponding to the internal commitment object. This is shorthand
    /// for `self.to_commitment().to_element()`.
    pub(crate) fn into_g1(self) -> G1Projective {
        self.into_commitment().to_element()
    }
}

impl ChallengeInput for BlindedMessage {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.0);
    }
}

/// A signature on a blinded message, generated using PS blind signing protocols.
///
/// This has the same representation as a regular [`Signature`], but different semantics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedSignature(Signature);

impl BlindedSignature {
    /// Sign a verified blinded message.
    pub fn new<const N: usize>(
        signing_keypair: &KeyPair<N>,
        rng: &mut impl Rng,
        msg: VerifiedBlindedMessage,
    ) -> Self {
        let u = Scalar::random(rng);

        BlindedSignature(Signature {
            sigma1: (signing_keypair.public_key().g1 * u).into(),
            sigma2: ((signing_keypair.sk.x1 + msg.into_g1()) * u).into(),
        })
    }

    /// Unblind a [`BlindedSignature`]. This will always compute: the user must take care to use
    /// a blinding factor that actually corresponds to the signature in order to retrieve
    /// a valid [`Signature`] on the original message.
    pub fn unblind(self, bf: BlindingFactor) -> Signature {
        let Self(Signature { sigma1, sigma2 }) = self;
        Signature {
            sigma1,
            sigma2: (sigma2 - (sigma1 * bf.as_scalar())).into(),
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
    pub fn as_bytes(&self) -> [u8; 96] {
        self.0.as_bytes()
    }

    /// Extract the sigma_1 or `h` component.
    pub fn sigma1(self) -> G1Affine {
        self.0.sigma1
    }

    /// Extract the sigma_2 or `H` component.
    pub fn sigma2(self) -> G1Affine {
        self.0.sigma2
    }
}

impl ChallengeInput for BlindedSignature {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.0);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::rng;

    #[cfg(feature = "bincode")]
    use crate::proofs::{SignatureProof, SignatureProofBuilder};

    #[test]
    fn verify_signed_message() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let sig = Signature::new(&mut rng, &kp, &msg);
        assert!(
            sig.verify(kp.public_key(), &msg),
            "Signature didn't verify!! {:?}, {:?}",
            kp,
            msg
        );
    }

    #[test]
    fn fail_verification_of_different_message() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let sig = Signature::new(&mut rng, &kp, &msg);
        let bad_msg = Message::<3>::random(&mut rng);

        assert_ne!(
            &*msg, &*bad_msg,
            "RNG failed to generate a different message."
        );
        assert!(
            !sig.verify(kp.public_key(), &bad_msg),
            "Signature verified on the wrong message!",
        );
    }

    #[test]
    fn fail_verification_with_wrong_keypair() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let bad_kp = KeyPair::new(&mut rng);
        let bad_sig = Signature::new(&mut rng, &bad_kp, &msg);

        assert!(
            !bad_sig.verify(kp.public_key(), &msg),
            "Signature from a different keypair verified!",
        );
    }

    #[test]
    fn fail_unit_signature() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let bad_sig = Signature {
            sigma1: G1Affine::identity(),
            sigma2: G1Projective::random(&mut rng).into(),
        };

        assert!(
            !bad_sig.verify(kp.public_key(), &msg),
            "Bad signature with sigma1 = 1 verified!"
        );
    }

    #[test]
    fn randomized_signatures_verify() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let mut sig = Signature::new(&mut rng, &kp, &msg);
        sig.randomize(&mut rng);

        assert!(sig.verify(kp.public_key(), &msg))
    }

    #[test]
    fn blind_signing_verifies() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let bf = BlindingFactor::new(&mut rng);
        let blinded_msg = msg.blind(kp.public_key(), bf);
        // Manually generate a verified blinded message - this skips the proof step.
        let verified_blinded_msg = VerifiedBlindedMessage(blinded_msg.0);

        let blind_sig = BlindedSignature::new(&kp, &mut rng, verified_blinded_msg);
        let sig = blind_sig.unblind(bf);

        assert!(
            sig.verify(kp.public_key(), &msg),
            "Signature didn't verify!!"
        );
    }

    #[test]
    fn blind_signing_requires_correct_blinding_factor() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let bf = BlindingFactor::new(&mut rng);
        let blinded_msg = msg.blind(kp.public_key(), bf);
        // Manually generate a verified blinded message - this skips the proof step.
        let verified_blinded_msg = VerifiedBlindedMessage(blinded_msg.0);

        let blind_sig = BlindedSignature::new(&kp, &mut rng, verified_blinded_msg);

        let bad_bf = BlindingFactor::new(&mut rng);
        let sig = blind_sig.unblind(bad_bf);

        assert!(
            !sig.verify(kp.public_key(), &msg),
            "Signature verified!! (with wrong blinding factor, *not* good, *do not* want this)"
        );
    }

    #[test]
    fn blind_signature_randomization_commutes() {
        let mut rng = rng();
        let kp = KeyPair::new(&mut rng);
        let msg = Message::<3>::random(&mut rng);

        let bf = BlindingFactor::new(&mut rng);
        let blind_sig = Signature::new(&mut rng, &kp, &msg).blind_and_randomize(&mut rng, bf);
        let sig = blind_sig.unblind(bf);

        assert!(
            sig.verify(kp.public_key(), &msg),
            "Signature didn't verify!!"
        );
    }

    /// Test if a proof fails when generated on a signature with the identity element at both positions.
    /// Also test that serializing/deserializing such proof does not work.
    ///
    /// This test happens inside this module because using our code one cannot create these bad signatures from outside the module.
    #[test]
    #[cfg(feature = "bincode")]
    fn signature_proof_from_sig_with_identities() {
        run_signature_proof_from_sig_with_identities::<1>();
        run_signature_proof_from_sig_with_identities::<2>();
        run_signature_proof_from_sig_with_identities::<3>();
        run_signature_proof_from_sig_with_identities::<5>();
        run_signature_proof_from_sig_with_identities::<8>();
        run_signature_proof_from_sig_with_identities::<13>();
    }

    #[cfg(feature = "bincode")]
    fn run_signature_proof_from_sig_with_identities<const N: usize>() {
        let mut rng = rng();
        let kp = KeyPair::<N>::new(&mut rng);
        let msg = Message::<N>::random(&mut rng);
        let mut bad_sig = Signature::new(&mut rng, &kp, &msg);
        bad_sig.sigma1 = G1Affine::identity();
        bad_sig.sigma2 = G1Affine::identity();
        assert!(!bad_sig.is_well_formed());

        build_proof_on_invalid_signature::<N>(bad_sig);
    }

    /// Test if a proof fails when generated on a signature with the identity element at the first position.
    /// Also test that serializing/deserializing such proof does not work.
    ///
    /// This test happens inside this module because using our code one cannot create these bad signatures from outside the module.
    #[test]
    #[cfg(feature = "bincode")]
    fn signature_proof_from_sig_with_identity_first() {
        run_signature_proof_from_sig_with_identity_first::<1>();
        run_signature_proof_from_sig_with_identity_first::<2>();
        run_signature_proof_from_sig_with_identity_first::<3>();
        run_signature_proof_from_sig_with_identity_first::<5>();
        run_signature_proof_from_sig_with_identity_first::<8>();
        run_signature_proof_from_sig_with_identity_first::<13>();
    }

    #[cfg(feature = "bincode")]
    fn run_signature_proof_from_sig_with_identity_first<const N: usize>() {
        let mut rng = rng();
        let kp = KeyPair::<N>::new(&mut rng);
        let msg = Message::<N>::random(&mut rng);
        let mut bad_sig = Signature::new(&mut rng, &kp, &msg);
        bad_sig.sigma1 = G1Affine::identity();
        assert!(!bad_sig.is_well_formed());

        build_proof_on_invalid_signature::<N>(bad_sig);
    }

    #[cfg(feature = "bincode")]
    fn build_proof_on_invalid_signature<const N: usize>(sig: Signature) {
        let mut rng = rng();
        let msg = Message::<N>::random(&mut rng);
        let kp = KeyPair::new(&mut rng);

        // Construct proof.
        let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
            &mut rng,
            msg,
            sig,
            &[None; N],
            kp.public_key(),
        );
        let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
        let proof = sig_proof_builder.generate_proof_response(challenge);
        let verif_challenge = ChallengeBuilder::new().with(&proof).finish();

        // Proof must not verify, since the underlying sig is invalid.
        assert!(!proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));

        // When serializing and deserializing, validation should not allow for this proof to be deserialized
        let ser_proof = bincode::serialize(&proof).unwrap();
        assert!(bincode::deserialize::<SignatureProof<N>>(&ser_proof).is_err());
    }

    /// Test the validation code during deserialization of the public key
    #[test]
    #[cfg(feature = "bincode")]
    fn serialize_deserialize_public_key() {
        run_serialize_deserialize_public_key::<1>();
        run_serialize_deserialize_public_key::<2>();
        run_serialize_deserialize_public_key::<3>();
        run_serialize_deserialize_public_key::<5>();
        run_serialize_deserialize_public_key::<8>();
        run_serialize_deserialize_public_key::<13>();
    }

    #[cfg(feature = "bincode")]
    fn run_serialize_deserialize_public_key<const N: usize>() {
        let mut rng = rng();
        let kp = KeyPair::<N>::new(&mut rng);

        // Check normal serialization/deserialization
        let ser_pk = bincode::serialize(&kp.public_key()).unwrap();
        let new_pk = bincode::deserialize::<PublicKey<N>>(&ser_pk).unwrap();
        assert_eq!(kp.pk, new_pk);

        // Check validation when g1 in the public key is the identity element
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        wrong_kp.pk.g1 = G1Affine::identity();
        let ser_pk = bincode::serialize(&wrong_kp.public_key()).unwrap();
        assert!(bincode::deserialize::<PublicKey<N>>(&ser_pk).is_err());

        // Check validation when g2 in the public key is the identity element
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        wrong_kp.pk.g2 = G2Affine::identity();
        let ser_pk = bincode::serialize(&wrong_kp.public_key()).unwrap();
        assert!(bincode::deserialize::<PublicKey<N>>(&ser_pk).is_err());

        // Check validation when x2 in the public key is the identity element
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        wrong_kp.pk.x2 = G2Affine::identity();
        let ser_pk = bincode::serialize(&wrong_kp.public_key()).unwrap();
        assert!(bincode::deserialize::<PublicKey<N>>(&ser_pk).is_err());

        // Check validation when y1s in the public key are the identity element
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        for i in 0..N {
            wrong_kp.pk.y1s[i] = G1Affine::identity();
        }
        let ser_pk = bincode::serialize(&wrong_kp.public_key()).unwrap();
        assert!(bincode::deserialize::<PublicKey<N>>(&ser_pk).is_err());

        // Check validation when y2s in the public key are the identity element
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        for i in 0..N {
            wrong_kp.pk.y2s[i] = G2Affine::identity();
        }
        let ser_pk = bincode::serialize(&wrong_kp.public_key()).unwrap();
        assert!(bincode::deserialize::<PublicKey<N>>(&ser_pk).is_err());
    }

    /// Test the validation code during deserialization of the secret key
    #[test]
    #[cfg(feature = "bincode")]
    fn serialize_deserialize_secret_key() {
        run_serialize_deserialize_secret_key::<1>();
        run_serialize_deserialize_secret_key::<2>();
        run_serialize_deserialize_secret_key::<3>();
        run_serialize_deserialize_secret_key::<5>();
        run_serialize_deserialize_secret_key::<8>();
        run_serialize_deserialize_secret_key::<13>();
    }

    #[cfg(feature = "bincode")]
    fn run_serialize_deserialize_secret_key<const N: usize>() {
        let mut rng = rng();
        let kp = KeyPair::<N>::new(&mut rng);

        // Check normal serialization/deserialization
        let ser_sk = bincode::serialize(&kp.sk).unwrap();
        let new_sk = bincode::deserialize::<SecretKey<N>>(&ser_sk).unwrap();
        assert_eq!(kp.sk, new_sk);

        // Check validation when x in the secret key is zero
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        wrong_kp.sk.x = Scalar::zero();
        let ser_sk = bincode::serialize(&wrong_kp.sk).unwrap();
        assert!(bincode::deserialize::<SecretKey<N>>(&ser_sk).is_err());

        // Check validation when x1 in the secret key is the identity element
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        wrong_kp.sk.x1 = G1Affine::identity();
        let ser_sk = bincode::serialize(&wrong_kp.sk).unwrap();
        assert!(bincode::deserialize::<SecretKey<N>>(&ser_sk).is_err());

        // Check validation when ys in the secret key are zero
        let mut wrong_kp = KeyPair::<N>::new(&mut rng);
        for i in 0..N {
            wrong_kp.sk.ys[i] = Scalar::zero();
        }
        let ser_sk = bincode::serialize(&wrong_kp.sk).unwrap();
        assert!(bincode::deserialize::<SecretKey<N>>(&ser_sk).is_err());
    }

    /// Test the validation code during deserialization of the signature
    #[test]
    #[cfg(feature = "bincode")]
    fn serialize_deserialize_signature() {
        run_serialize_deserialize_signature::<1>();
        run_serialize_deserialize_signature::<2>();
        run_serialize_deserialize_signature::<3>();
        run_serialize_deserialize_signature::<5>();
        run_serialize_deserialize_signature::<8>();
        run_serialize_deserialize_signature::<13>();
    }

    #[cfg(feature = "bincode")]
    fn run_serialize_deserialize_signature<const N: usize>() {
        let mut rng = rng();
        let kp = KeyPair::<N>::new(&mut rng);
        let msg = Message::<N>::random(&mut rng);
        let sig = Signature::new(&mut rng, &kp, &msg);

        // Check normal serialization/deserialization
        let ser_sig = bincode::serialize(&sig).unwrap();
        let new_sig = bincode::deserialize::<Signature>(&ser_sig).unwrap();
        assert_eq!(sig, new_sig);

        // Check validation when the first element of the signature is the identity element
        let mut wrong_sig = sig;
        wrong_sig.sigma1 = G1Affine::identity();
        let ser_sig = bincode::serialize(&wrong_sig).unwrap();
        assert!(bincode::deserialize::<Signature>(&ser_sig).is_err());
    }
}
