//! Functionality for building challenge scalars.
//!
//! Supports challenges on proofs of knowledge of the opening of commitments, the opening of
//! signatures, and range constraints, both individually and in conjunctions. There is also support for
//! incorporating other public information into the challenge.

use crate::common::*;
use group::GroupEncoding;
use sha3::{Digest, Sha3_256};
use std::{convert::TryFrom, ops::Mul};

/// A trait implemented by types which can feed their public components into a [`ChallengeBuilder`].
pub trait ChallengeInput {
    /// Incorporate public components of this type into a [`ChallengeBuilder`].
    fn consume(&self, builder: &mut ChallengeBuilder);
}

impl<'a, T: ChallengeInput> ChallengeInput for &'a T {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        (**self).consume(builder);
    }
}

impl ChallengeInput for Scalar {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G1Affine {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G2Affine {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G1Projective {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G2Projective {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

/// A challenge scalar for use in a Schnorr-style proof.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Challenge(Scalar);

impl Challenge {
    /// Retrieve the internal scalar value.
    pub fn to_scalar(self) -> Scalar {
        self.0
    }
}

impl Mul<Scalar> for Challenge {
    type Output = Scalar;
    fn mul(self, rhs: Scalar) -> Self::Output {
        self.0 * rhs
    }
}

/// Holds state used when building a [`Challenge`] using the Fiat-Shamir heuristic, as in a
/// non-interactive Schnorr proof.
///
/// # Usage
/// A [`Challenge`] should integrate any public information shared by the prover and
/// the verifier. The parties must integrate the elements in the same order.
/// Types that can be integrated into the challenge should implement the [`ChallengeInput`] trait.
///
/// This library includes convenience functions to generate identical `Challenge`s from the
/// `Builder` type held by the prover and the corresponding `Proof` held by the verifier.
///
/// ```
/// # use zkchannels_crypto::{Message, pedersen::PedersenParameters, proofs::{CommitmentProofBuilder, ChallengeBuilder}};
/// # use bls12_381::{Scalar, G1Projective};
/// # let mut rng = rand::thread_rng();
/// # let pedersen_parameters: PedersenParameters<G1Projective, 1> = PedersenParameters::new(&mut rng);
/// # let msg = Message::new([Scalar::from(100)]);
/// # let commitment_scalars = [None];
/// // The prover constructs a proof builder...
/// let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
///     &mut rng,
///     msg,
///     &commitment_scalars,
///     &pedersen_parameters
/// );
///
/// // ...and uses it to form a challenge
/// let prover_challenge = ChallengeBuilder::new()
///     .with(&proof_builder)
///     .with(&pedersen_parameters)
///     .finish();
///
/// let proof = proof_builder.generate_proof_response(prover_challenge);
///
/// // The verifier uses the corresponding proof to form the challenge
/// let verifier_challenge = ChallengeBuilder::new()
///     .with(&proof)
///     .with(&pedersen_parameters)
///     .finish();
///
/// assert_eq!(prover_challenge, verifier_challenge);
/// # assert!(proof.verify_knowledge_of_opening(&pedersen_parameters, verifier_challenge));
/// ```
///
/// Other relevant types are already held by both parties, such as
/// [`PedersenParameters`](crate::pedersen::PedersenParameters),
/// [`PublicKey`](crate::pointcheval_sanders::PublicKey)s, and
/// [`RangeConstraintParameters`](crate::proofs::RangeConstraintParameters). Additional
/// constraints on the proof must be manually added to the challenge; see details in the
/// [constraints documentation](crate::proofs#constraints).
///  
/// **Secure challenge construction:**
/// Reuse attacks are possible when the challenge does
/// not change between separate proving sessions. We recommend integrating shared, external
/// context, like a protocol transcript, to avoid these attacks. Users can implement the
/// [`ChallengeInput`] trait for any such context or pass arbitrary bytes directly.
///
/// # Implementation details
///
/// This type does not derive `Clone` because standard use of a `Challenge` requires it to be
/// built out of public material at time of proof verification; this prevents misuse that could
/// arise from partially-constructed `ChallengeBuilder`s containing non-public material.
/// Also, challenge generation is efficient and it is typically not worth reusing a
/// `ChallengeBuilder`, even if the desired `Challenge`s consume similar inputs.
///
/// This implementation simulates a random oracle with the SHA3-256 hash function.
#[derive(Debug)]
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
    pub fn consume<T: ChallengeInput>(&mut self, object: &T) {
        object.consume(self);
    }

    /// A conveniently chainable variant of [`ChallengeBuilder::consume`].
    pub fn with<T: ChallengeInput>(mut self, object: &T) -> Self {
        object.consume(&mut self);
        self
    }

    /// Incorporate arbitrary bytes into the challenge.
    pub fn consume_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        self.hasher.update(bytes);
    }

    /// A conveniently chainable variant of [`ChallengeBuilder::consume_bytes`].
    pub fn with_bytes(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.consume_bytes(bytes);
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
