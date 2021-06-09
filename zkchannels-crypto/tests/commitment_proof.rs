use bls12_381::*;
use ff::Field;
use rand::SeedableRng;
use std::iter;
use zkchannels_crypto::{
    challenge::ChallengeBuilder,
    commitment_proof::CommitmentProofBuilder,
    message::{BlindingFactor, Message},
    pedersen_commitments::PedersenParameters,
};

// Seeded rng for replicable tests.
fn rng() -> (impl rand::CryptoRng + rand::RngCore) {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[test]
fn commitment_proof_verifies() {
    let mut rng = rng();
    let length = 3;

    // Generate message.
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );

    // Form commmitment.
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    // Build proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    let challenge = ChallengeBuilder::new()
        .with_commitment_proof(&proof_builder)
        .finish();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    // Proof must verify with the original commit.
    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());

    // Proof must not verify with a different commit.
    let bad_msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let bad_com = params.commit(&bad_msg, bf).unwrap();
    assert!(!proof
        .verify_knowledge_of_opening_of_commitment(&params, bad_com, challenge)
        .unwrap());
}

#[test]
#[should_panic(expected = "MessageLengthMismatch")]
fn commitment_proof_incorrect_message_length() {
    let mut rng = rng();
    let length = 3;

    // Generate short message.
    let wrong_msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length - 1)
            .collect(),
    );

    // Generate long parameters.
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);

    // Construct proof - response phase should fail since message and params are not the same length.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    let challenge = ChallengeBuilder::new()
        .with_commitment_proof(&proof_builder)
        .finish();
    let _proof = proof_builder
        .generate_proof_response(&wrong_msg, bf, challenge)
        .unwrap();
}

#[test]
fn commitment_proof_with_linear_relation() {
    let mut rng = rng();
    let length = 3;
    // Construct messages of the form [a, ., .]; [., ., a]
    // e.g. the last element of the second equals the first element of the first.
    let msg_vec1 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length)
        .collect::<Vec<Scalar>>();
    let mut msg_vec2 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length - 1)
        .collect::<Vec<Scalar>>();
    msg_vec2.push(msg_vec1[0]);
    let msg1 = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);

    // Construct commitments.
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf1 = BlindingFactor::new(&mut rng);
    let com1 = params.commit(&msg1, bf1).unwrap();
    let bf2 = BlindingFactor::new(&mut rng);
    let com2 = params.commit(&msg2, bf2).unwrap();

    // Construct proofs - commitment phase.
    let proof_builder1 =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    // Set commitment scalars for the matching elements to be equal:
    // Pass in the commitment scalar of the first position onto the third position.
    let proof_builder2 = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[
            None,
            None,
            Some(proof_builder1.conjunction_commitment_scalars()[0]),
        ],
        &params,
    )
    .unwrap();

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with_commitment_proof(&proof_builder1)
        .with_commitment_proof(&proof_builder2)
        .finish();

    // Complete proofs - response phase.
    let proof1 = proof_builder1
        .generate_proof_response(&msg1, bf1, challenge)
        .unwrap();
    let proof2 = proof_builder2
        .generate_proof_response(&msg2, bf2, challenge)
        .unwrap();

    // Verify both proofs.
    assert!(proof1
        .verify_knowledge_of_opening_of_commitment(&params, com1, challenge)
        .unwrap());
    assert!(proof2
        .verify_knowledge_of_opening_of_commitment(&params, com2, challenge)
        .unwrap());

    // Verify linear equation.
    assert_eq!(
        proof1.conjunction_response_scalars()[0],
        proof2.conjunction_response_scalars()[2]
    );
    // Verify the above was not an accident.
    assert_ne!(
        proof1.conjunction_response_scalars()[0],
        proof2.conjunction_response_scalars()[0]
    );
    assert_ne!(
        proof1.conjunction_response_scalars()[1],
        proof2.conjunction_response_scalars()[1]
    );
    assert_ne!(
        proof1.conjunction_response_scalars()[2],
        proof2.conjunction_response_scalars()[2]
    );
}

#[test]
fn commitment_proof_with_public_value() {
    let mut rng = rng();
    let length = 3;

    // Construct message and commitment.
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    // Construct proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    // Save commitment scalars for public elements (in this case, all of them).
    let commitment_scalars = proof_builder.conjunction_commitment_scalars().to_vec();
    let challenge = ChallengeBuilder::new()
        .with_commitment_proof(&proof_builder)
        .finish();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    // Verify underlying proof.
    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());

    // Verify response scalars are correctly formed against the public msg.
    let response_scalars = proof.conjunction_response_scalars();
    assert_eq!(
        msg[0] * challenge.0 + commitment_scalars[0],
        response_scalars[0]
    );
    assert_eq!(
        msg[1] * challenge.0 + commitment_scalars[1],
        response_scalars[1]
    );
    assert_eq!(
        msg[2] * challenge.0 + commitment_scalars[2],
        response_scalars[2]
    );
}

#[test]
fn commitment_proof_with_linear_relation_public_addition() {
    let mut rng = rng();

    // Construct messages of the form [a]; [a + public_value]
    // e.g. the last element of the second equals the first element of the first.
    let public_value = Scalar::random(&mut rng);
    let msg_vec1 = vec![Scalar::random(&mut rng)];
    let msg_vec2 = vec![msg_vec1[0] + public_value];
    let msg1 = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);

    // Construct commitments.
    let params = PedersenParameters::<G1Projective>::new(1, &mut rng);
    let bf1 = BlindingFactor::new(&mut rng);
    let com1 = params.commit(&msg1, bf1).unwrap();
    let bf2 = BlindingFactor::new(&mut rng);
    let com2 = params.commit(&msg2, bf2).unwrap();

    // Construct proof - commitment phase.
    let proof_builder1 =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 1], &params).unwrap();
    // Commitment scalars for elements with linear relationships must match.
    let proof_builder2 = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[Some(proof_builder1.conjunction_commitment_scalars()[0])],
        &params,
    )
    .unwrap();

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with_commitment_proof(&proof_builder1)
        .with_commitment_proof(&proof_builder2)
        .finish();
    let proof1 = proof_builder1
        .generate_proof_response(&msg1, bf1, challenge)
        .unwrap();
    let proof2 = proof_builder2
        .generate_proof_response(&msg2, bf2, challenge)
        .unwrap();

    // Verify both proofs.
    assert!(proof1
        .verify_knowledge_of_opening_of_commitment(&params, com1, challenge)
        .unwrap());
    assert!(proof2
        .verify_knowledge_of_opening_of_commitment(&params, com2, challenge)
        .unwrap());

    // Verify linear equation.
    assert_eq!(
        proof1.conjunction_response_scalars()[0] + challenge.0 * public_value,
        proof2.conjunction_response_scalars()[0]
    );
}
