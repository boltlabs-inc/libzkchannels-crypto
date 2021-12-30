use bls12_381::{G1Projective, Scalar};
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    proofs::{ChallengeBuilder, CommitmentProof, CommitmentProofBuilder},
    Message, Rng,
};

/// Note on encoding: this small example does not clearly specify an input domain, so we
/// just take the direct encoding of small values. See Message docs for more details.
fn main() {
    let mut rng = rand::thread_rng();
    let pedersen_params = PedersenParameters::new(&mut rng);

    let public_value = Scalar::from(123456789);

    let public_opening_proof = PartialOpeningProof::new(
        &mut rng,
        &pedersen_params,
        public_value,
        Scalar::from(777666555),
    );

    assert!(public_opening_proof.verify(&pedersen_params, public_value));
}

/// A zero-knowledge proof of knowledge of the opening (x, y) of a commitment,
/// where the first element x is a known public value.
struct PartialOpeningProof {
    pub public_value: Scalar,
    pub public_value_commitment_scalar: Scalar,
    pub commitment_proof: CommitmentProof<G1Projective, 2>,
}

impl PartialOpeningProof {
    /// Generate a new `PartialOpeningProof` with the given parameters.
    ///
    /// * `public_value` - x, or the first element of the message tuple, which will be public
    /// * `secret_value` - y, or the second element of the message tuple, which will not be
    ///   revealed
    pub fn new(
        rng: &mut impl Rng,
        pedersen_params: &PedersenParameters<G1Projective, 2>,
        public_value: Scalar,
        secret_value: Scalar,
    ) -> Self {
        // Generate a message tuple with a public and secret part
        let msg = Message::new([public_value, secret_value]);

        // Start building the proof
        let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            msg,
            &[None; 2],
            pedersen_params,
        );

        // Save the commitment scalar corresponding to `public_value` (the first in the tuple)
        let public_value_commitment_scalar = proof_builder.conjunction_commitment_scalars()[0];

        // Construct challenge with _all_ public components of the proof
        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&public_value_commitment_scalar)
            .with(&public_value)
            .with(pedersen_params)
            .finish();

        // Finish building the proof and assemble components
        PartialOpeningProof {
            public_value,
            public_value_commitment_scalar,
            commitment_proof: proof_builder.generate_proof_response(challenge),
        }
    }

    pub fn verify(
        &self,
        pedersen_params: &PedersenParameters<G1Projective, 2>,
        expected_public_value: Scalar,
    ) -> bool {
        let challenge = ChallengeBuilder::new()
            .with(&self.commitment_proof)
            .with(&self.public_value_commitment_scalar)
            .with(&self.public_value)
            .with(pedersen_params)
            .finish();

        // 1. Make sure the public value is correct
        let public_value_matches_expected = expected_public_value == self.public_value;

        // 2. Make sure the proof is correctly constructed with respect to the public value
        //    and its commitment scalar.
        let public_value_matches_proof = self.commitment_proof.conjunction_response_scalars()[0]
            == challenge * self.public_value + self.public_value_commitment_scalar;

        // 3. Make sure the commitment proof is valid
        let proof_verifies = self
            .commitment_proof
            .verify_knowledge_of_opening(pedersen_params, challenge);

        public_value_matches_expected && public_value_matches_proof && proof_verifies
    }
}
