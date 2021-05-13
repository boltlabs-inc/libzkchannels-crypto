//! Generates proofs of knowledge of the opening of a signature.
//!
//! FIXME (marcella) - cite all the papers
//!
use crate::{
    challenge::ChallengeScalar,
    pedersen_commitments::{
        Commitment, CommitmentProof, CommitmentProofBuilder, CommitmentRandomness,
    },
    ps_blind_signatures::{BlindedMessage, BlindedSignature, BlindingFactor},
    ps_keys::PublicKey,
    ps_signatures::Signature,
    types::*,
};

use group::Group;

#[derive(Debug, Clone)]
pub struct SignatureProof {
    pub message_commitment: Commitment<G2Projective>,
    pub blinded_signature: BlindedSignature,
    pub commitment_proof: CommitmentProof<G2Projective>,
}

#[derive(Debug, Clone)]
pub struct SignatureProofBuilder<'a> {
    pub message: &'a Message,
    pub message_commitment: Commitment<G2Projective>,
    pub message_commitment_randomness: CommitmentRandomness,
    pub blinded_signature: BlindedSignature,
    pub commitment_proof_builder: CommitmentProofBuilder<G2Projective>,
}

impl<'a> SignatureProofBuilder<'a> {
    /// Run the commitment phase of a Schnorr-style signature proof.
    ///
    /// The `maybe_commitment_scalars` argument allows the caller to choose particular commitment
    /// scalars in the case that they need to satisfy some sort of constraint, for example when
    /// implementing equality or linear combination constraints on top of the proof.
    pub fn generate_commitment_phase_objects(
        rng: &mut impl Rng,
        message: &'a Message,
        signature: Signature,
        maybe_commitment_scalars: &[Option<Scalar>],
        params: &PublicKey,
    ) -> Self {
        let params = params.as_g2_pedersen_parameters();
        let commitment_proof_builder = CommitmentProofBuilder::generate_commitment_phase_objects(
            rng,
            maybe_commitment_scalars,
            &params,
        );

        let blinding_factor = BlindingFactor::new(rng);
        let blinded_signature = BlindedSignature::from_signature(&signature, blinding_factor);

        let message_commitment_randomness = CommitmentRandomness(blinding_factor.0);
        let message_commitment = params.commit(message, message_commitment_randomness);

        Self {
            message,
            message_commitment,
            message_commitment_randomness,
            blinded_signature,
            commitment_proof_builder,
        }
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_object(self, challenge_scalar: ChallengeScalar) -> SignatureProof {
        let commitment_proof = self.commitment_proof_builder.generate_proof_object(
            self.message,
            self.message_commitment_randomness,
            challenge_scalar,
        );

        SignatureProof {
            message_commitment: self.message_commitment,
            blinded_signature: self.blinded_signature,
            commitment_proof,
        }
    }
}
