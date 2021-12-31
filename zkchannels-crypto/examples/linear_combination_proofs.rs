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

/// This example generates three different proofs, each demonstrating a different fundamental piece
/// of a modular linear combination. That is, each proof demonstrates a piece of the following
/// equation, where (a, b, c) are public values, (x, y, z) are secret values, and q is the modulus of
/// the BLS12-381 Scalar field:
/// a*x + b*y + c === z (mod q)
///
/// Note on encoding: these small examples do not clearly specify an input domain, so we
/// just take the direct encoding of small values. See Message docs for more details.
fn main() {
    let mut rng = rand::thread_rng();
    let pedersen_parameters = PedersenParameters::new(&mut rng);
    let key_pair = KeyPair::new(&mut rng);

    // Build and verify a proof with a sum of secret values (x + y = z)
    let double_message_proof = SecretSumProof::new(
        &mut rng,
        &key_pair,
        &pedersen_parameters,
        &[Scalar::from(25), Scalar::from(300)],
    );
    assert!(double_message_proof.verify(key_pair.public_key(), &pedersen_parameters));

    // Build and verify a proof with a sum of a secret and a public value (x + c = z)
    let values = [Scalar::from(10), Scalar::from(100)];
    let fixed_difference_proof =
        FixedDifferenceProof::new(&mut rng, &pedersen_parameters, &values, Scalar::from(90));
    assert!(fixed_difference_proof.verify(&pedersen_parameters, Scalar::from(90)));

    // It's possible to make an invalid fixed difference proof! It won't verify because the
    // difference between the two values is not 10
    // A better implementation would return an error type indicating why it failed.
    let bad_fixed_difference_proof =
        FixedDifferenceProof::new(&mut rng, &pedersen_parameters, &values, Scalar::from(10));
    assert!(!bad_fixed_difference_proof.verify(&pedersen_parameters, Scalar::from(10)));

    // Build and verify a proof with a product of a secret and a public value (a * x = z)
    let key_pair = KeyPair::new(&mut rng);
    let product_proof = PublicProductProof::new(&mut rng, &key_pair, &values, Scalar::from(10));
    assert!(product_proof.verify(key_pair.public_key(), Scalar::from(10)));
    assert!(!product_proof.verify(key_pair.public_key(), Scalar::from(90)));
}
/// Zero-knowledge proof of knowledge of a signature on a message (z) and of the opening (x, y)
/// of a commitment, such that x + y === z (mod q).
/// This is an additive linear combination of secret values.
struct SecretSumProof {
    summands: CommitmentProof<G1Projective, 2>,
    sum: SignatureProof<1>,
}

impl SecretSumProof {
    /// Create a new `SecretSumProof` with the given parameters. This constructor validates inputs:
    /// it will not produce a `SecretSumProof` on values x, y, z where x + y != z (mod q).
    ///
    /// * `numbers` - [x, y], or the two values that will be summed.
    pub fn new(
        rng: &mut impl Rng,
        key_pair: &KeyPair<1>,
        pedersen_parameters: &PedersenParameters<G1Projective, 2>,
        numbers: &[Scalar; 2],
    ) -> Self {
        // Compute and sign sum
        let sum = Message::from(numbers[0] + numbers[1]);
        let sum_signature = sum.sign(rng, key_pair);

        // Form commitment proof builder to summands
        let summands = Message::new(*numbers);
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

        // Generate challenge with all public data related to the proof:
        // - commitment proof statement & commitment (via `summand_proof_builder`)
        // - signature proof statement & blinded signature (via `sum_proof_builder`)
        // - public key corresponding to the blinded signature
        // - commitment parameters
        let challenge = ChallengeBuilder::new()
            .with(&summand_proof_builder)
            .with(&sum_proof_builder)
            .with(key_pair.public_key())
            .with(pedersen_parameters)
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
        let responses_sum =
            self.sum.conjunction_response_scalars()[0] == summand_scalars[0] + summand_scalars[1];

        // Reconstruct challenge with all public data related to the proof:
        // - commitment proof statement & commitment (via `self.summands`, a `CommitmentProof`)
        // - signature proof statement & blinded signature (via `self.sum`, a `SignatureProof`)
        // - public key corresponding to the blinded signature
        // - commitment parameters
        let challenge = ChallengeBuilder::new()
            .with(&self.summands)
            .with(&self.sum)
            .with(public_key)
            .with(pedersen_parameters)
            .finish();

        // Check that proofs verify
        let sum_proof_verifies = self
            .sum
            .verify_knowledge_of_signature(public_key, challenge);
        let summand_proof_verifies = self
            .summands
            .verify_knowledge_of_opening(pedersen_parameters, challenge);

        responses_sum && sum_proof_verifies && summand_proof_verifies
    }
}

/// Zero-knowledge proof of knowledge of two values that differ by a fixed amount:
/// x + c === z (mod q).
/// This is an additive linear combination of a secret and a public value.
struct FixedDifferenceProof {
    proof: CommitmentProof<G1Projective, 2>,
    difference: Scalar,
}

impl FixedDifferenceProof {
    /// Generate a new `FixedDifferenceProof`. This constructor does _not_ validate inputs; the proof
    /// may not verify if the `values` do not differ by `difference`.
    ///
    /// * `values` - [x, z], or the two numbers that will form the commitment in the proof
    /// * `difference` - c, or the expected difference between the values
    pub fn new(
        rng: &mut impl Rng,
        pedersen_parameters: &PedersenParameters<G1Projective, 2>,
        values: &[Scalar; 2],
        difference: Scalar,
    ) -> Self {
        // Form commitment proof builder to the two values
        let message = Message::new(*values);

        // Generate commitment proof builder with matching commitment scalars for the values that differ
        let matching_commitment_scalar = Some(Scalar::random(&mut *rng));
        let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            message,
            &[matching_commitment_scalar, matching_commitment_scalar],
            pedersen_parameters,
        );

        // Generate challenge with all public data related to the proof:
        // - commitment proof statement & commitment (via `proof_builder`)
        // - public value describing the expected difference
        // - commitment parameters
        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&difference)
            .with(pedersen_parameters)
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
        expected_difference: Scalar,
    ) -> bool {
        // Check that expected difference matches the one in the proof
        let difference_matches = self.difference == expected_difference;

        // Reconstruct challenge with all public data related to the proof:
        // - commitment proof statement & commitment (via `self.proof`)
        // - public value describing the expected difference
        // - commitment parameters
        let challenge = ChallengeBuilder::new()
            .with(&self.proof)
            .with(&self.difference)
            .with(pedersen_parameters)
            .finish();

        // Check that the response scalars have the correct relationship
        let response_scalars = self.proof.conjunction_response_scalars();
        let responses_differ_correctly =
            response_scalars[1] == response_scalars[0] + challenge * self.difference;

        // Check that the proof verifies
        let proof_verifies = self
            .proof
            .verify_knowledge_of_opening(pedersen_parameters, challenge);

        difference_matches && responses_differ_correctly && proof_verifies
    }
}

/// Zero knowledge proof of knowledge of a signature over two values (x, y) that differ by a given
/// multiplier (a). That is, x * a === y (mod q).
pub struct PublicProductProof {
    proof: SignatureProof<2>,
    multiplier: Scalar,
}

impl PublicProductProof {
    /// Generate a new `PublicProductProof`. This constructor does not validate inputs; the proof
    /// may not verify if the `values` do not differ by the `multiplier`.
    ///
    /// * `values` - [x, y], or the two values for which the described equation should hold
    /// * `multiplier` - a, or the expected multiplier
    pub fn new(
        rng: &mut impl Rng,
        key_pair: &KeyPair<2>,
        values: &[Scalar; 2],
        multiplier: Scalar,
    ) -> Self {
        // Form a signature over the values
        let message = Message::new(*values);
        let signature = message.sign(rng, key_pair);

        // Generate signature proof builder with coordinating commitment scalars for the values
        let commitment_scalar = Scalar::random(&mut *rng);
        let proof_builder = SignatureProofBuilder::generate_proof_commitments(
            rng,
            message,
            signature,
            &[
                Some(commitment_scalar),
                Some(commitment_scalar * multiplier),
            ],
            key_pair.public_key(),
        );

        // Generate challenge with all public data related to the proof:
        // - signature proof statement & blinded signature (via `proof_builder`)
        // - public value describing the expected multiplier
        // - public key corresponding to the blinded signature
        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&multiplier)
            .with(key_pair.public_key())
            .finish();

        // Form the proof
        Self {
            proof: proof_builder.generate_proof_response(challenge),
            multiplier,
        }
    }

    pub fn verify(&self, public_key: &PublicKey<2>, expected_multiplier: Scalar) -> bool {
        // Check that the multiplier matches the one in the proof
        let multiplier_is_correct = expected_multiplier == self.multiplier;

        // Check that the response scalars have the correct relationship
        let response_scalars = self.proof.conjunction_response_scalars();
        let responses_correspond = response_scalars[1] == response_scalars[0] * self.multiplier;

        // Reconstruct challenge with all public data related to the proof:
        // - signature proof statement & blinded signature (via `self.proof`)
        // - public value describing the expected multiplier
        // - public key corresponding to the blinded signature
        let challenge = ChallengeBuilder::new()
            .with(&self.proof)
            .with(&self.multiplier)
            .with(public_key)
            .finish();

        // Check that the proof verifies
        let proof_verifies = self
            .proof
            .verify_knowledge_of_signature(public_key, challenge);

        multiplier_is_correct && responses_correspond && proof_verifies
    }
}
