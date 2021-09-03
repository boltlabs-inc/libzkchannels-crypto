//! Proof of knowledge of a Pointcheval Sanders signature.

use crate::{
    common::*,
    pedersen::ToPedersenParameters,
    pointcheval_sanders::{BlindedSignature, PublicKey, Signature},
    proofs::{
        Challenge, ChallengeBuilder, ChallengeInput, CommitmentProof, CommitmentProofBuilder,
    },
};
use group::Curve;
use serde::{Deserialize, Serialize};
use std::ops::Neg;

/// Fully constructed proof of knowledge of a signature.
/// (that is, of a [`Signature`] and the underlying [`Message`] tuple).
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
    /// Run the commitment phase of a Schnorr-style signature proof
    /// to prove knowledge of the message tuple `message` and the `signature`.
    ///
    /// The `conjunction_commitment_scalars` argument allows the caller to choose particular
    /// commitment scalars to create additional constraints.
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        message: Message<N>,
        signature: Signature,
        conjunction_commitment_scalars: &[Option<Scalar>; N],
        params: &PublicKey<N>,
    ) -> Self {
        // Commitment phase of PoK of the message tuple (using signature parameters).
        let commitment_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            message,
            conjunction_commitment_scalars,
            &params.to_pedersen_parameters(),
        );

        // Blind and randomize signature
        let blinded_signature =
            signature.blind_and_randomize(rng, commitment_proof_builder.message_blinding_factor());

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
    pub fn generate_proof_response(self, challenge: Challenge) -> SignatureProof<N> {
        // Run response phase for PoK of opening of commitment to message
        let commitment_proof = self
            .commitment_proof_builder
            .generate_proof_response(challenge);

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
            .verify_knowledge_of_opening(&params.to_pedersen_parameters(), challenge);

        // commitment proof matches blinded signature
        let commitment_proof_matches_signature = multi_miller_loop(&[
            (
                &self.blinded_signature.sigma1(),
                &(((params.x2 + self.commitment_proof.commitment().to_element()).to_affine())
                    .into()),
            ),
            (&self.blinded_signature.sigma2(), &params.g2.neg().into()),
        ])
        .final_exponentiation()
            == Gt::identity();

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::pedersen::Commitment;
    use crate::test::rng;
    use crate::SerializeElement;
    use ff::Field;

    pub struct CommitmentProofBuilderWithPublicFields<G: Group<Scalar = Scalar>, const N: usize> {
        pub msg: Message<N>,
        pub commitment: Commitment<G>,
        pub message_blinding_factor: BlindingFactor,
        pub scalar_commitment: Commitment<G>,
        pub blinding_factor_commitment_scalar: Scalar,
        pub message_commitment_scalars: Box<[Scalar; N]>,
    }

    #[test]
    #[cfg(feature = "bincode")]
    fn test_signature_proof_challenge() {
        let mut rng = rng();

        let msg = Message::<5>::random(&mut rng);
        let mut ser_commitment = Vec::<u8>::new();
        let mut serializer = bincode::Serializer::new(&mut ser_commitment, bincode::options());
        SerializeElement::serialize(&G2Projective::random(&mut rng), &mut serializer).unwrap();
        let commitment = bincode::deserialize::<Commitment<G2Projective>>(&ser_commitment).unwrap();
        let mut ser_signature = Vec::<u8>::new();
        let mut serializer = bincode::Serializer::new(&mut ser_signature, bincode::options());
        SerializeElement::serialize(&G1Projective::random(&mut rng), &mut serializer).unwrap();
        SerializeElement::serialize(&G1Projective::random(&mut rng), &mut serializer).unwrap();
        let signature = bincode::deserialize::<BlindedSignature>(&ser_signature).unwrap();
        let bf = BlindingFactor::new(&mut rng);
        let proof_builder = CommitmentProofBuilderWithPublicFields {
            msg,
            commitment,
            message_blinding_factor: bf,
            scalar_commitment: commitment,
            blinding_factor_commitment_scalar: Scalar::random(&mut rng),
            message_commitment_scalars: Box::new([Scalar::random(&mut rng); 5]),
        };
        let sig_proof_builder = SignatureProofBuilder::<5> {
            blinded_signature: signature,
            commitment_proof_builder: unsafe { std::mem::transmute(proof_builder) },
        };
        let builder_challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
        let proof = sig_proof_builder.generate_proof_response(builder_challenge);
        let proof_challenge = ChallengeBuilder::new().with(&proof).finish();
        assert_eq!(builder_challenge.to_scalar(), proof_challenge.to_scalar());
    }
}
