use bls12_381::{G1Projective, Scalar};
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    pointcheval_sanders::{KeyPair, PublicKey},
    proofs::{
        ChallengeBuilder, CommitmentProof, CommitmentProofBuilder, SignatureProof,
        SignatureProofBuilder,
    },
    Message, Rng,
};

fn main() {
    let mut rng = rand::thread_rng();
    let pedersen_parameters = PedersenParameters::new(&mut rng);
    let key_pair = KeyPair::new(&mut rng);

    // Build and verify a proof with a sum of secret values
    let double_message_proof =
        SecretSumProof::new(&mut rng, &key_pair, &pedersen_parameters, &[25, 300]);
    assert!(double_message_proof.verify(key_pair.public_key(), &pedersen_parameters));

    // TODO: Build and verify a proof with a sum of a secret and a public value

    // TODO: Build and verify a proof with a product of a secret and a public value
}
/// Zero-knowledge proof of knowledge of a signature on a message that is the sum of two committed
/// values
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
