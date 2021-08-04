use crate::{
    common::*,
    pointcheval_sanders::{BlindedMessage, PublicKey, VerifiedBlindedMessage},
    proofs::{Challenge, CommitmentProof, CommitmentProofBuilder},
};
use serde::{Deserialize, Serialize};

use super::{ChallengeBuilder, ChallengeInput};

/// Fully constructed proof of knowledge of the opening of a blinded message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRequestProof<const N: usize> {
    /// Blinded message on which this proof is requesting a signature.
    blinded_message: BlindedMessage,
    /// Proof of knowledge of opening of the `message_commitment`.
    commitment_proof: CommitmentProof<G2Projective, N>,
}

/// A partially-built [`SignatureRequestProof`].
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct SignatureRequestProofBuilder<const N: usize> {
    /// Blinded message on which this proof is requesting a signature.
    blinded_message: BlindedMessage,
    /// Commitment phase output for the underlying proof of knowledge of the opening of the `message_commitment`.
    commitment_proof_builder: CommitmentProofBuilder<G2Projective, N>,
}

#[allow(unused)]
impl<const N: usize> SignatureRequestProofBuilder<N> {
    /// Run the commitment phase of a Schnorr-style signature proof.
    ///
    /// The `conjunction_commitment_scalars` argument allows the caller to choose particular
    /// commitment scalars in the case that they need to satisfy some sort of constraint, for
    /// example when implementing equality or linear combination constraints on top of the proof.
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        msg: &Message<N>,
        conjunction_commitment_scalars: &[Option<Scalar>; N],
        params: &PublicKey<N>,
    ) -> Self {
        todo!()
    }

    /// Get the commitment scalars corresponding to the message tuple to use when constructing
    /// conjunctions of proofs.
    ///
    /// This does not include the commitment scalar corresponding to the blinding factor.
    pub fn conjunction_commitment_scalars(&self) -> &[Scalar; N] {
        self.commitment_proof_builder
            .conjunction_commitment_scalars()
    }

    /// Get the blinding factor for the message.
    pub fn message_blinding_factor(&self) -> BlindingFactor {
        todo!()
    }

    /// Get the [`BlindedMessage`].
    pub fn blinded_message(&self) -> BlindedMessage {
        todo!()
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(self, challenge_scalar: Challenge) -> SignatureRequestProof<N> {
        todo!()
    }
}

impl<const N: usize> ChallengeInput for SignatureRequestProofBuilder<N> {
    fn consume(&self, _builder: &mut ChallengeBuilder) {
        todo!()
    }
}

#[allow(unused)]
impl<const N: usize> SignatureRequestProof<N> {
    /// Check that a [`SignatureRequestProof`] is valid.
    ///
    /// Returns a blind-signable [`VerifiedBlindedMessage`] if so, or `None` if the proof is not valid.
    ///
    /// This verifies that the internal commitment proof is valid.
    pub fn verify_knowledge_of_blinded_message(
        &self,
        params: &PublicKey<N>,
        challenge: Challenge,
    ) -> Option<VerifiedBlindedMessage> {
        todo!()
    }

    /// Get the response scalars corresponding to the message to verify conjunctions of proofs.
    ///
    /// This does not include the response scalar for the blinding factor.
    pub fn conjunction_response_scalars(&self) -> &[Scalar; N] {
        self.commitment_proof.conjunction_response_scalars()
    }

    /// Get the [`BlindedMessage`] on which this proof is requesting a signature.
    pub fn blinded_message(&self) -> BlindedMessage {
        todo!()
    }
}

impl<const N: usize> ChallengeInput for SignatureRequestProof<N> {
    fn consume(&self, _builder: &mut ChallengeBuilder) {
        todo!()
    }
}
