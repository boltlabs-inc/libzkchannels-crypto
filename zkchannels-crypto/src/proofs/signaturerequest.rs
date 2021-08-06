//! Proof of knowledge of the opening of a blinded message (e.g. a Pedesen commitment formed with
//! parameters derived from a Pointcheval Sanders public key).
//! To be used to verify messages for Pointcheval Sanders blind signatures.

use crate::{
    common::*,
    pointcheval_sanders::{BlindedMessage, PublicKey, VerifiedBlindedMessage},
    proofs::{Challenge, CommitmentProof, CommitmentProofBuilder},
};
use serde::{Deserialize, Serialize};

use super::{ChallengeBuilder, ChallengeInput};

/// Fully constructed proof of knowledge of the opening of a blinded message.
/// (that is, of a [`Message`] tuple).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRequestProof<const N: usize> {
    /// Proof of knowledge of opening of a blinded message.
    commitment_proof: CommitmentProof<G2Projective, N>,
}

/// A partially-built [`SignatureRequestProof`];
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct SignatureRequestProofBuilder<const N: usize> {
    /// Commitment phase output for the underlying proof of knowledge of the opening of the
    /// blinded message.
    commitment_proof_builder: CommitmentProofBuilder<G2Projective, N>,
}

#[allow(unused)]
impl<const N: usize> SignatureRequestProofBuilder<N> {
    /// Run the commitment phase of a Schnorr-style signature request proof
    /// to prove knowledge of the message tuple `msg`.
    ///
    /// The `conjunction_commitment_scalars` argument allows the caller to choose particular
    /// commitment scalars to create additional constraints.
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
