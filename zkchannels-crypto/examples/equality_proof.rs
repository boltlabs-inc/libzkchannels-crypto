use bls12_381::{G1Projective, Scalar};
use ff::Field;
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    proofs::{ChallengeBuilder, CommitmentProof, CommitmentProofBuilder, SignatureProof},
    Message, Rng,
};

/// Zero knowledge proof of knowledge of a message tuple that repeats itself
/// e.g. (x, x).
pub struct RepeatedMessageProof {
    proof: CommitmentProof<G1Projective, 2>,
}

impl RepeatedMessageProof {
    pub fn new(
        rng: &mut impl Rng,
        pedersen_parameters: &PedersenParameters<G1Projective, 2>,
        secret_value: u64,
    ) -> Self {
        let msg = Message::new([Scalar::from(secret_value), Scalar::from(secret_value)]);

        // Generate a commitment scalar *uniformly at random* to use for the matching elements.
        let matching_commitment_scalar = Scalar::random(&mut *rng);

        // Start building the commitment proof, using a matching commitment scalar
        let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            msg,
            &[
                Some(matching_commitment_scalar),
                Some(matching_commitment_scalar),
            ],
            pedersen_parameters,
        );

        // Generate challenge - the only public part of this proof is the proof itself, which
        // includes the proof statement (the commitment to msg).
        let challenge = ChallengeBuilder::new().with(&proof_builder).finish();

        // Finish the proof.
        Self {
            proof: proof_builder.generate_proof_response(challenge),
        }
    }

    pub fn verify(&self, pedersen_parameters: &PedersenParameters<G1Projective, 2>) -> bool {
        // 1. Check that the response scalars for the matching elements, match.
        let responses_match = self.proof.conjunction_response_scalars()[0]
            == self.proof.conjunction_response_scalars()[1];
        let challenge = ChallengeBuilder::new().with(&self.proof).finish();
        let proof_verifies = self
            .proof
            .verify_knowledge_of_opening_of_commitment(pedersen_parameters, challenge);

        responses_match && proof_verifies
    }
}

/// Zero knowledge proof of knowledge of a signature and an opening such that
/// - the signature is on a message tuple of the form (x, _)
/// - the opening is on a message tuple of the form (_, x)
/// for some secret x.
pub struct FlipFlopSignatureProof {
    _first: SignatureProof<2>,
    _second: CommitmentProof<G1Projective, 2>,
}

fn main() {
    let mut rng = rand::thread_rng();
    let pedersen_parameters = PedersenParameters::new(&mut rng);

    // Build and verify a double message proof
    let double_message_proof = RepeatedMessageProof::new(&mut rng, &pedersen_parameters, 1000);
    assert!(double_message_proof.verify(&pedersen_parameters));

    // TODO: build and verify a flip-flop proof.
}
