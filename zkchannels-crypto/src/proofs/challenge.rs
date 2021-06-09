//! Functionality for building challenge scalars.
//!
//! Supports challenges on proofs of knowledge of the opening of commitments, the opening of
//! signatures, and range proofs, both individually and in conjunctions. There is also support for
//! incorporating other public information into the challenge.

use crate::{
    common::*,
    pedersen::{Commitment, PedersenParameters},
    pointcheval_sanders::{BlindedSignature, PublicKey, Signature},
    proofs::{
        CommitmentProof, CommitmentProofBuilder, RangeProof, RangeProofBuilder, SignatureProof,
        SignatureProofBuilder,
    },
};
use group::{Group, GroupEncoding};
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;

/// A trait implemented by types which can feed their public components into a [`ChallengeBuilder`].
pub trait ChallengeDigest {
    /// Incorporate public components of this type into a [`ChallengeBuilder`].
    fn digest(&self, builder: &mut ChallengeBuilder);
}

impl<'a, T: ChallengeDigest> ChallengeDigest for &'a T {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        (**self).digest(builder);
    }
}

impl ChallengeDigest for Scalar {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.to_bytes());
    }
}

impl ChallengeDigest for G1Affine {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.to_bytes());
    }
}

impl ChallengeDigest for G2Affine {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.to_bytes());
    }
}

impl ChallengeDigest for G1Projective {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.to_bytes());
    }
}

impl ChallengeDigest for G2Projective {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.to_bytes());
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

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeDigest
    for PedersenParameters<G, N>
{
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.h.to_bytes());
        for g in &self.gs {
            builder.digest_bytes(g.to_bytes());
        }
    }
}

impl ChallengeDigest for Signature {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.sigma1());
        builder.digest(&self.sigma2());
    }
}

impl ChallengeDigest for BlindedSignature {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.to_internal_blinded_signature());
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding> ChallengeDigest for Commitment<G> {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.to_element().to_bytes());
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeDigest
    for CommitmentProofBuilder<G, N>
{
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.scalar_commitment);
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeDigest
    for CommitmentProof<G, N>
{
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.scalar_commitment);
    }
}

impl<const N: usize> ChallengeDigest for SignatureProofBuilder<N> {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.message_commitment);
        builder.digest(&self.blinded_signature);
        builder.digest(&self.commitment_proof_builder);
    }
}

impl<const N: usize> ChallengeDigest for SignatureProof<N> {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest(&self.message_commitment);
        builder.digest(&self.blinded_signature);
        builder.digest(&self.commitment_proof);
    }
}

impl ChallengeDigest for RangeProofBuilder {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        for digit_proof in &self.digit_proof_builders {
            builder.digest(digit_proof);
        }
    }
}

impl ChallengeDigest for RangeProof {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        for digit_proof in &self.digit_proofs {
            builder.digest(digit_proof);
        }
    }
}

/// A challenge scalar for use in a Schnorr-style proof.
#[derive(Debug, Clone, Copy)]
pub struct Challenge(Scalar);

impl Challenge {
    /// Retrieve the internal scalar value.
    pub fn to_scalar(self) -> Scalar {
        self.0
    }
}

/// Holds state used when building a [`Challenge`] using the Fiat-Shamir heuristic, as in a
/// non-interactive Schnorr proof.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct ChallengeBuilder {
    hasher: Sha3_256,
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeBuilder {
    /// Initialize a new, empty challenge.
    pub fn new() -> Self {
        Self {
            hasher: Sha3_256::new(),
        }
    }

    /// Incorporate public data from some given type into the challenge.
    pub fn digest<T: ChallengeDigest>(&mut self, object: &T) {
        object.digest(self);
    }

    /// A conveniently chainable variant of [`ChallengeBuilder::digest`].
    pub fn with<T: ChallengeDigest>(mut self, object: &T) -> Self {
        object.digest(&mut self);
        self
    }

    /// Incorporate arbitrary bytes into the challenge.
    pub fn digest_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        self.hasher.update(bytes);
    }

    /// A conveniently chainable variant of [`ChallengeBuilder::digest_bytes`].
    pub fn with_bytes(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.digest_bytes(bytes);
        self
    }

    /// Consume the builder and generate a [`Challenge`] from the accumulated data.
    pub fn finish(self) -> Challenge {
        let mut digested = [0; 32];
        digested.copy_from_slice(self.hasher.finalize().as_ref());
        let scalar = Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[24..32]).unwrap()),
        ]);
        Challenge(scalar)
    }
}
