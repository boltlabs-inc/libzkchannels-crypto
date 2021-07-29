use crate::{
    common::*,
    pedersen::ToPedersenParameters,
    pointcheval_sanders::{BlindedSignature, PublicKey, Signature},
    proofs::{
        Challenge, ChallengeBuilder, ChallengeInput, CommitmentProof, CommitmentProofBuilder,
    },
};
use serde::{Deserialize, Serialize};

/// Fully constructed proof of knowledge of a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureProof<const N: usize> {
    /// Blinded, randomized version of the signature.
    blinded_signature: BlindedSignature,
    /// Proof of knowledge of opening of the `message_commitment`.
    commitment_proof: CommitmentProof<G2Projective, N>,
}

/// A partially-built [`SignatureProof`].
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct SignatureProofBuilder<const N: usize> {
    /// Randomized and blinded version of the original signature.
    blinded_signature: BlindedSignature,
    /// Commitment phase output for the underlying proof of knowledge of the opening of the `message_commitment`.
    commitment_proof_builder: CommitmentProofBuilder<G2Projective, N>,
}

impl<const N: usize> SignatureProofBuilder<N> {
    /// Run the commitment phase of a Schnorr-style signature proof.
    ///
    /// The `conjunction_commitment_scalars` argument allows the caller to choose particular
    /// commitment scalars in the case that they need to satisfy some sort of constraint, for
    /// example when implementing equality or linear combination constraints on top of the proof.
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        message: Message<N>,
        signature: Signature,
        conjunction_commitment_scalars: &[Option<Scalar>; N],
        params: &PublicKey<N>,
    ) -> Self {
        // Run commitment phase for PoK of opening of commitment to message.
        let pedersen_params = params.to_pedersen_parameters();

        // Run signature proof setup phase:
        // Form commitment to blinding factor + message
        let commitment_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            message,
            conjunction_commitment_scalars,
            &pedersen_params,
        );

        // Blind and randomize signature
        let mut blinded_signature = BlindedSignature::blind(
            signature,
            commitment_proof_builder.message_blinding_factor(),
        );
        blinded_signature.randomize(rng);

        Self {
            blinded_signature,
            commitment_proof_builder,
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

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(self, challenge_scalar: Challenge) -> SignatureProof<N> {
        // Run response phase for PoK of opening of commitment to message
        let commitment_proof = self
            .commitment_proof_builder
            .generate_proof_response(challenge_scalar);

        SignatureProof {
            blinded_signature: self.blinded_signature,
            commitment_proof,
        }
    }
}

impl<const N: usize> ChallengeInput for SignatureProofBuilder<N> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.blinded_signature);
        builder.consume(&self.commitment_proof_builder);
    }
}

impl<const N: usize> SignatureProof<N> {
    /// Check that a [`SignatureProof`] is valid.
    ///
    /// Checks that:
    ///
    /// - the blinded signature is correctly formed (first element is non-identity)
    /// - the internal commitment proof is valid
    /// - the commitment proof is formed on the same message as the blinded signature
    pub fn verify_knowledge_of_signature(
        &self,
        params: &PublicKey<N>,
        challenge: Challenge,
    ) -> bool {
        // signature is well-formed
        let valid_signature = self.blinded_signature.is_well_formed();

        // commitment proof is valid
        let valid_commitment_proof = self
            .commitment_proof
            .verify_knowledge_of_opening_of_commitment(
                &params.to_pedersen_parameters(),
                //        &PedersenParameters::<G2Projective, N>::from_public_key(params),
                challenge,
            );

        // commitment proof matches blinded signature
        let commitment_proof_matches_signature =
            pairing(
                &self.blinded_signature.sigma1(),
                &(params.x2 + self.commitment_proof.commitment().to_element()).into(),
            ) == pairing(&self.blinded_signature.sigma2(), &params.g2);

        valid_signature && valid_commitment_proof && commitment_proof_matches_signature
    }

    /// Get the response scalars corresponding to the message to verify conjunctions of proofs.
    ///
    /// This does not include the response scalar for the blinding factor.
    pub fn conjunction_response_scalars(&self) -> &[Scalar; N] {
        self.commitment_proof.conjunction_response_scalars()
    }
}

impl<const N: usize> ChallengeInput for SignatureProof<N> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.blinded_signature);
        builder.consume(&self.commitment_proof);
    }
}
