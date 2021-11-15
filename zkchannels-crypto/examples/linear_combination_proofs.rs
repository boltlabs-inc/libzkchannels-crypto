use zkchannels_crypto::{
    pedersen::PedersenParameters,
    pointcheval_sanders::{KeyPair, PublicKey},
    proofs::{
        ChallengeBuilder, CommitmentProof, CommitmentProofBuilder, SignatureProof,
        SignatureProofBuilder,
    },
    Message, Rng,
};
use {
    bls12_381::{G1Projective, Scalar},
    ff::Field,
};

// This example generates three different proofs, each demonstrating a different fundamental piece
// of a linear combination.
fn main() {
    let mut rng = rand::thread_rng();
    let pedersen_parameters = PedersenParameters::new(&mut rng);
    let key_pair = KeyPair::new(&mut rng);

    // Build and verify a proof with a sum of secret values
    let double_message_proof =
        SecretSumProof::new(&mut rng, &key_pair, &pedersen_parameters, &[25, 300]);
    assert!(double_message_proof.verify(key_pair.public_key(), &pedersen_parameters));

    // Build and verify a proof with a sum of a secret and a public value
    let values = [10, 100];
    let fixed_difference_proof =
        FixedDifferenceProof::new(&mut rng, &pedersen_parameters, &values, 90);
    assert!(fixed_difference_proof.verify(&pedersen_parameters, 90));

    // It's possible to make an invalid fixed difference proof! It won't verify because the
    // difference between the two values is not 10
    // A better implementation would return an error type indicating why it failed.
    let bad_fixed_difference_proof =
        FixedDifferenceProof::new(&mut rng, &pedersen_parameters, &values, 10);
    assert!(!bad_fixed_difference_proof.verify(&pedersen_parameters, 10));

    // Build and verify a proof with a product of a secret and a public value
    let key_pair = KeyPair::new(&mut rng);
    let product_proof = PublicProductProof::new(&mut rng, &key_pair, &values, 10);
    assert!(product_proof.verify(key_pair.public_key(), 10));
    assert!(!product_proof.verify(key_pair.public_key(), 90));
}
/// Zero-knowledge proof of knowledge of a signature on a message that is the sum of two committed
/// values (an additive linear combination of secret values).
struct SecretSumProof {
    summands: CommitmentProof<G1Projective, 2>,
    sum: SignatureProof<1>,
}

impl SecretSumProof {
    pub fn new(
        rng: &mut impl Rng,
        key_pair: &KeyPair<1>,
        pedersen_parameters: &PedersenParameters<G1Projective, 2>,
        numbers: &[u64; 2],
    ) -> Self {
        // Compute and sign sum
        let sum = Message::from(Scalar::from(numbers[0] + numbers[1]));
        let sum_signature = sum.sign(rng, key_pair);

        // Form commitment proof builder to summands
        let summands = Message::new([Scalar::from(numbers[0]), Scalar::from(numbers[1])]);
        let summand_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            summands,
            &[None, None],
            pedersen_parameters,
        );

        // Form signature proof, setting the commitment scalar to the sum of the summands'
        // commitment scalars
        let summand_scalars = summand_proof_builder.conjunction_commitment_scalars();
        let sum_proof_builder = SignatureProofBuilder::generate_proof_commitments(
            rng,
            sum,
            sum_signature,
            &[Some(summand_scalars[0] + summand_scalars[1])],
            key_pair.public_key(),
        );

        // Form challenge
        let challenge = ChallengeBuilder::new()
            .with(&summand_proof_builder)
            .with(&sum_proof_builder)
            .finish();

        // Execute response phase of proofs
        Self {
            summands: summand_proof_builder.generate_proof_response(challenge),
            sum: sum_proof_builder.generate_proof_response(challenge),
        }
    }

    pub fn verify(
        &self,
        public_key: &PublicKey<1>,
        pedersen_parameters: &PedersenParameters<G1Projective, 2>,
    ) -> bool {
        // Check that response scalars have the expected relationship
        let summand_scalars = self.summands.conjunction_response_scalars();
        let response_scalars_sum =
            self.sum.conjunction_response_scalars()[0] == summand_scalars[0] + summand_scalars[1];

        let challenge = ChallengeBuilder::new()
            .with(&self.summands)
            .with(&self.sum)
            .finish();

        // Check that proofs verify
        let sum_proof_verifies = self
            .sum
            .verify_knowledge_of_signature(public_key, challenge);
        let summand_proof_verifies = self
            .summands
            .verify_knowledge_of_opening(pedersen_parameters, challenge);

        response_scalars_sum && sum_proof_verifies && summand_proof_verifies
    }
}

/// Zero-knowledge proof of knowledge of two values that differ by a fixed amount
/// (an additive linear combination of a secret and a public value).
struct FixedDifferenceProof {
    proof: CommitmentProof<G1Projective, 2>,
    difference: Scalar,
}

impl FixedDifferenceProof {
    /// Generate a new `FixedDifferenceProof`. Note that this does not validate inputs; the proof
    /// may not verify if the `values` do not differ by `difference`.
    pub fn new(
        rng: &mut impl Rng,
        pedersen_parameters: &PedersenParameters<G1Projective, 2>,
        values: &[u64; 2],
        difference: u64,
    ) -> Self {
        // Form commitment proof builder to the two values
        let scalar_values = Message::new([Scalar::from(values[0]), Scalar::from(values[1])]);
        let difference = Scalar::from(difference);

        // Generate commitment proof builder with matching commitment scalars for the values that differ
        let matching_commitment_scalar = Some(Scalar::random(&mut *rng));
        let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            scalar_values,
            &[matching_commitment_scalar, matching_commitment_scalar],
            pedersen_parameters,
        );

        // Form the challenge
        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&difference)
            .finish();

        // Form the proof
        Self {
            proof: proof_builder.generate_proof_response(challenge),
            difference,
        }
    }

    pub fn verify(
        &self,
        pedersen_parameters: &PedersenParameters<G1Projective, 2>,
        expected_difference: u64,
    ) -> bool {
        // Check that expected difference matches the one in the proof
        let difference_matches = self.difference == Scalar::from(expected_difference);

        let challenge = ChallengeBuilder::new()
            .with(&self.proof)
            .with(&self.difference)
            .finish();

        // Check that the response scalars have the correct relationship
        let response_scalars = self.proof.conjunction_response_scalars();
        let response_scalars_differ_correctly =
            response_scalars[1] == response_scalars[0] + challenge * self.difference;

        // Check that the proof verifies
        let proof_verifies = self
            .proof
            .verify_knowledge_of_opening(pedersen_parameters, challenge);

        difference_matches && response_scalars_differ_correctly && proof_verifies
    }
}

/// Zero knowledge proof of knowledge of a signature over two values that differ by a given 
/// multiplier.
pub struct PublicProductProof {
    proof: SignatureProof<2>,
    multiplier: Scalar,
}

impl PublicProductProof {
    /// Generate a new `PublicProductProof`. Note that this does not validate inputs; the proof
    /// may not verify if the `values` do not differ by the `multiplier`.
    pub fn new(
        rng: &mut impl Rng,
        key_pair: &KeyPair<2>,
        values: &[u64; 2],
        multiplier: u64,
    ) -> Self {
        // Form a signature over the values
        let scalar_values = Message::new([Scalar::from(values[0]), Scalar::from(values[1])]);
        let multiplier = Scalar::from(multiplier);
        let signature = scalar_values.sign(rng, key_pair);

        // Generate signature proof builder with coordinating commitment scalars for the values
        let commitment_scalar = Scalar::random(&mut *rng);
        let proof_builder = SignatureProofBuilder::generate_proof_commitments(
            rng,
            scalar_values,
            signature,
            &[
                Some(commitment_scalar),
                Some(commitment_scalar * multiplier),
            ],
            key_pair.public_key(),
        );

        // Form the challenge
        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&multiplier)
            .finish();

        // Form the proof
        Self {
            proof: proof_builder.generate_proof_response(challenge),
            multiplier,
        }
    }

    pub fn verify(&self, public_key: &PublicKey<2>, expected_multiplier: u64) -> bool {
        // Check that the multiplier matches the one in the proof
        let multiplier_is_correct = Scalar::from(expected_multiplier) == self.multiplier;

        // Check that the response scalars have the correct relationship
        let response_scalars = self.proof.conjunction_response_scalars();
        let response_scalars_correspond =
            response_scalars[1] == response_scalars[0] * self.multiplier;

        let challenge = ChallengeBuilder::new()
            .with(&self.proof)
            .with(&self.multiplier)
            .finish();

        // Check that the proof verifies
        let proof_verifies = self
            .proof
            .verify_knowledge_of_signature(public_key, challenge);

        multiplier_is_correct && response_scalars_correspond && proof_verifies
    }
}
