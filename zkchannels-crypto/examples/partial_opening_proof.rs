use bls12_381::{G1Projective, Scalar};
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    proofs::{ChallengeBuilder, CommitmentProof, CommitmentProofBuilder},
    Message, Rng,
};

struct PartialOpeningProof {
    pub public_value: Scalar,
    pub public_value_commitment_scalar: Scalar,
    pub commitment_proof: CommitmentProof<G1Projective, 2>,
}

impl PartialOpeningProof {
    pub fn new(
        rng: &mut impl Rng,
        pedersen_params: &PedersenParameters<G1Projective, 2>,
        public_value: u64,
        secret_value: u64,
    ) -> Self {
        // Generate a message tuple with a public and secret part.
        let public_value = Scalar::from(public_value);
        let secret_value = Scalar::from(secret_value);
        let msg = Message::new([public_value, secret_value]);

        // Start building the proof.
        let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            msg,
            &[None; 2],
            pedersen_params,
        );

        // Save the commitment scalar corresponding to `public_value` (the first in the tuple)
        let public_value_commitment_scalar = proof_builder.conjunction_commitment_scalars()[0];

        // Construct challenge with _all_ public components of the proof.
        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&public_value_commitment_scalar)
            .with(&public_value)
            .finish();

        // Finish building the proof and assemble components.
        PartialOpeningProof {
            public_value,
            public_value_commitment_scalar,
            commitment_proof: proof_builder.generate_proof_response(challenge),
        }
    }

    pub fn verify(
        &self,
        pedersen_params: &PedersenParameters<G1Projective, 2>,
        expected_public_value: u64,
    ) -> bool {
        let challenge = ChallengeBuilder::new()
            .with(&self.commitment_proof)
            .with(&self.public_value_commitment_scalar)
            .with(&self.public_value)
            .finish();

        // 1. Make sure the public value is correct.
        let public_value_matches_expected =
            Scalar::from(expected_public_value) == self.public_value;

        // 2. Make sure the proof is correctly constructed with respect to the public value
        //    and its commitment scalar.
        let public_value_matches_proof = self.commitment_proof.conjunction_response_scalars()[0]
            == challenge * self.public_value + self.public_value_commitment_scalar;

        // 3. Make sure the commitment proof is valid.
        let proof_validates = self
            .commitment_proof
            .verify_knowledge_of_opening(pedersen_params, challenge);

        public_value_matches_expected && public_value_matches_proof && proof_validates
    }
}
fn main() {
    let mut rng = rand::thread_rng();
    let pedersen_params = PedersenParameters::new(&mut rng);

    let public_value = 123456789;

    let public_opening_proof =
        PartialOpeningProof::new(&mut rng, &pedersen_params, public_value, 777666555);

    assert!(public_opening_proof.verify(&pedersen_params, public_value));
}
