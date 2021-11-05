use bls12_381::{G1Projective, Scalar};
use ff::Field;
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    pointcheval_sanders::{KeyPair, PublicKey},
    proofs::{
        ChallengeBuilder, CommitmentProof, CommitmentProofBuilder, SignatureProof,
        SignatureProofBuilder,
    },
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

        // Generate a commitment scalar *uniformly at random* to use for the matching elements
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
        // includes the proof statement (the commitment to msg)
        let challenge = ChallengeBuilder::new().with(&proof_builder).finish();

        // Finish the proof.
        Self {
            proof: proof_builder.generate_proof_response(challenge),
        }
    }

    pub fn verify(&self, pedersen_parameters: &PedersenParameters<G1Projective, 2>) -> bool {
        // 1. Check that the response scalars for the matching elements, match
        let responses_match = self.proof.conjunction_response_scalars()[0]
            == self.proof.conjunction_response_scalars()[1];
        let challenge = ChallengeBuilder::new().with(&self.proof).finish();

        // 2. Check that the commitment proof verifies
        let proof_verifies = self
            .proof
            .verify_knowledge_of_opening(pedersen_parameters, challenge);

        responses_match && proof_verifies
    }
}

/// Zero knowledge proof of knowledge of a signature and an opening such that
/// - the signature is on a message tuple of the form (x, _)
/// - the opening is on a message tuple of the form (_, x)
/// for some secret x.
pub struct FlipFlopSignatureProof {
    first: SignatureProof<2>,
    second: CommitmentProof<G1Projective, 2>,
}

impl FlipFlopSignatureProof {
    pub fn new(
        rng: &mut impl Rng,
        signature_parameters: &KeyPair<2>,
        commitment_parameters: &PedersenParameters<G1Projective, 2>,
        signed_value: u64,
        committed_value: u64,
        shared_value: u64,
    ) -> Self {
        // Format the two specific messages
        let signed_message = Message::new([Scalar::from(shared_value), Scalar::from(signed_value)]);
        let committed_message =
            Message::new([Scalar::from(committed_value), Scalar::from(shared_value)]);

        // Procure a signature on the signed message (in some cases, this could generated by a
        // different party and passed as an argument to the proof)
        let signature = signed_message.sign(rng, signature_parameters);

        // Generate the signature proof
        let signature_proof_builder = SignatureProofBuilder::generate_proof_commitments(
            rng,
            signed_message,
            signature,
            &[None, None],
            signature_parameters.public_key(),
        );

        // Generate the commitment proof, reusing the commitment scalar for the message that is
        // shared between the two proofs.
        let commitment_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            committed_message,
            &[
                None,
                Some(signature_proof_builder.conjunction_commitment_scalars()[0]),
            ],
            commitment_parameters,
        );

        let challenge = ChallengeBuilder::new()
            .with(&signature_proof_builder)
            .with(&commitment_proof_builder)
            .finish();

        Self {
            first: signature_proof_builder.generate_proof_response(challenge),
            second: commitment_proof_builder.generate_proof_response(challenge),
        }
    }

    pub fn verify(
        &self,
        public_key: &PublicKey<2>,
        commitment_parameters: &PedersenParameters<G1Projective, 2>,
    ) -> bool {
        // Make sure matching elements have matching response scalars
        let elements_match = self.first.conjunction_response_scalars()[0]
            == self.second.conjunction_response_scalars()[1];

        // Regenerate challenge
        let challenge = ChallengeBuilder::new()
            .with(&self.first)
            .with(&self.second)
            .finish();

        // Make sure signature proof verifies
        let signature_proof_verifies = self
            .first
            .verify_knowledge_of_signature(public_key, challenge);

        // Make sure commitment proof verifies
        let commitment_proof_verifies = self
            .second
            .verify_knowledge_of_opening(commitment_parameters, challenge);

        elements_match && signature_proof_verifies && commitment_proof_verifies
    }
}

fn main() {
    let mut rng = rand::thread_rng();
    let pedersen_parameters = PedersenParameters::new(&mut rng);

    // Build and verify a double message proof
    let double_message_proof = RepeatedMessageProof::new(&mut rng, &pedersen_parameters, 1000);
    assert!(double_message_proof.verify(&pedersen_parameters));

    let signature_parameters = KeyPair::new(&mut rng);
    let flip_flop_proof = FlipFlopSignatureProof::new(
        &mut rng,
        &signature_parameters,
        &pedersen_parameters,
        31,
        13,
        987654,
    );

    assert!(flip_flop_proof.verify(signature_parameters.public_key(), &pedersen_parameters));
}
