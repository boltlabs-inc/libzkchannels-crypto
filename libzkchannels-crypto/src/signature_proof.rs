//! Generates proofs of knowledge of a signed message.
//!
//! FIXME (marcella) - cite all the papers
//!
use crate::{
    challenge::Challenge,
    commitment_proof::{CommitmentProof, CommitmentProofBuilder},
    pedersen_commitments::{Commitment, CommitmentRandomness},
    ps_blind_signatures::{BlindedSignature, BlindingFactor},
    ps_keys::PublicKey,
    ps_signatures::Signature,
    types::*,
};

/// Fully constructed proof of knowledge of a signed message.
#[derive(Debug, Clone)]
pub struct SignatureProof {
    /// Commitment to the signed message.
    pub message_commitment: Commitment<G2Projective>,
    /// Blinded, randomized version of the signature.
    pub blinded_signature: BlindedSignature,
    /// Proof of knowledge of opening of the `message_commitment`.
    pub commitment_proof: CommitmentProof<G2Projective>,
}

/// A partially-built [`SignatureProof`].
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct SignatureProofBuilder {
    /// Underlying message in the signature.
    pub message: Message,
    /// Commitment to the message.
    pub message_commitment: Commitment<G2Projective>,
    /// Commitment randomness corresponding to the `message_commitment`.
    pub message_commitment_randomness: CommitmentRandomness,
    /// Randomized and blinded version of the original signature.
    pub blinded_signature: BlindedSignature,
    /// Commitment phase output for the underlying proof of knowledge of the opening of the `message_commitment`.
    pub commitment_proof_builder: CommitmentProofBuilder<G2Projective>,
}

impl SignatureProofBuilder {
    /// Run the commitment phase of a Schnorr-style signature proof.
    ///
    /// The `maybe_commitment_scalars` argument allows the caller to choose particular commitment
    /// scalars in the case that they need to satisfy some sort of constraint, for example when
    /// implementing equality or linear combination constraints on top of the proof.
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        message: Message,
        signature: Signature,
        maybe_commitment_scalars: &[Option<Scalar>],
        params: &PublicKey,
    ) -> Self {
        // Run commitment phase for PoK of opening of commitment to message.
        let params = params.to_g2_pedersen_parameters();
        let commitment_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            maybe_commitment_scalars,
            &params,
        );

        // Run signature proof setup phase:
        // Blind and randomize signature
        let blinding_factor = BlindingFactor::new(rng);
        let mut blinded_signature = BlindedSignature::from_signature(&signature, blinding_factor);
        blinded_signature.randomize(rng);

        // Form commitment to blinding factor + message
        let message_commitment_randomness = CommitmentRandomness(blinding_factor.0);
        let message_commitment = params.commit(&message, message_commitment_randomness);

        Self {
            message,
            message_commitment,
            message_commitment_randomness,
            blinded_signature,
            commitment_proof_builder,
        }
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(self, challenge_scalar: Challenge) -> SignatureProof {
        // Run response phase for PoK of opening of commitment to message
        let commitment_proof = self.commitment_proof_builder.generate_proof_response(
            &self.message,
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
