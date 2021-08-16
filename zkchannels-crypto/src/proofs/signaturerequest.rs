//! Proof of knowledge of the opening of a blinded message (e.g. a Pedesen commitment formed with
//! parameters derived from a Pointcheval Sanders public key).
//! To be used to verify messages for Pointcheval Sanders blind signatures.

use crate::{
    common::*,
    pedersen::ToPedersenParameters,
    pointcheval_sanders::{PublicKey, VerifiedBlindedMessage},
    proofs::{Challenge, CommitmentProof, CommitmentProofBuilder},
};
use serde::{Deserialize, Serialize};

use super::{ChallengeBuilder, ChallengeInput};

/// Fully constructed proof of knowledge of the opening of a blinded message.
/// (that is, of a [`Message`] tuple).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRequestProof<const N: usize> {
    /// Proof of knowledge of opening of a blinded message.
    commitment_proof: CommitmentProof<G1Projective, N>,
}

/// A partially-built [`SignatureRequestProof`];
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct SignatureRequestProofBuilder<const N: usize> {
    /// Commitment phase output for the underlying proof of knowledge of the opening of the
    /// blinded message.
    commitment_proof_builder: CommitmentProofBuilder<G1Projective, N>,
}

impl<const N: usize> SignatureRequestProofBuilder<N> {
    /// Run the commitment phase of a Schnorr-style signature request proof
    /// to prove knowledge of the message tuple `msg`.
    ///
    /// The `conjunction_commitment_scalars` argument allows the caller to choose particular
    /// commitment scalars to create additional constraints.
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        message: Message<N>,
        conjunction_commitment_scalars: &[Option<Scalar>; N],
        params: &PublicKey<N>,
    ) -> Self {
        // Commitment phase of PoK of the message tuple (using signature parameters).
        Self {
            commitment_proof_builder: CommitmentProofBuilder::generate_proof_commitments(
                rng,
                message,
                conjunction_commitment_scalars,
                &params.to_pedersen_parameters(),
            ),
        }
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
        self.commitment_proof_builder.message_blinding_factor()
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(self, challenge: Challenge) -> SignatureRequestProof<N> {
        // Run response phase for PoK of opening of commitment to message
        SignatureRequestProof {
            commitment_proof: self
                .commitment_proof_builder
                .generate_proof_response(challenge),
        }
    }
}

impl<const N: usize> ChallengeInput for SignatureRequestProofBuilder<N> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        self.commitment_proof_builder.consume(builder);
    }
}

impl<const N: usize> SignatureRequestProof<N> {
    /// Check that a [`SignatureRequestProof`] is valid.
    ///
    /// Returns a blind-signable [`VerifiedBlindedMessage`] if so, or `None` if the proof is not valid.
    ///
    /// This verifies that the internal commitment proof is valid.
    pub fn verify_knowledge_of_opening(
        &self,
        params: &PublicKey<N>,
        challenge: Challenge,
    ) -> Option<VerifiedBlindedMessage> {
        // commitment proof is valid
        self.commitment_proof
            .verify_knowledge_of_opening(&params.to_pedersen_parameters(), challenge)
            .then(|| VerifiedBlindedMessage(self.commitment_proof.commitment()))
    }

    /// Get the response scalars corresponding to the message to verify conjunctions of proofs.
    ///
    /// This does not include the response scalar for the blinding factor.
    pub fn conjunction_response_scalars(&self) -> &[Scalar; N] {
        self.commitment_proof.conjunction_response_scalars()
    }
}

impl<const N: usize> ChallengeInput for SignatureRequestProof<N> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        self.commitment_proof.consume(builder);
    }
}
