use bls12_381::*;
use ff::Field;
use std::iter;
use zkchannels_crypto::{
    challenge::ChallengeBuilder,
    commitment_proof::CommitmentProofBuilder,
    message::{BlindingFactor, Message},
    pedersen_commitments::PedersenParameters,
    Rng,
};

fn rng() -> impl Rng {
    use rand::SeedableRng;
    rand::rngs::StdRng::from_seed(*b"DON'T USE THIS FOR ANYTHING REAL")
}

#[test]
fn commitment_proof_verifies() {
    let mut rng = rng();
    let length = 3;
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    let challenge = ChallengeBuilder::new()
        .with_commitment_proof(&proof_builder)
        .finish();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
}

#[test]
#[should_panic(expected = "MessageLengthMismatch")]
fn commitment_proof_incorrect_message_length() {
    let mut rng = rng();
    let length = 3;
    let wrong_msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length - 1)
            .collect(),
    );
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);

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
    let msg_vec1 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length)
        .collect::<Vec<Scalar>>();
    // Create random message of which the last element is equal to the first element of the first msg
    let mut msg_vec2 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length - 1)
        .collect::<Vec<Scalar>>();
    msg_vec2.push(msg_vec1[0]);
    let msg1 = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf1 = BlindingFactor::new(&mut rng);
    let com1 = params.commit(&msg1, bf1).unwrap();
    let bf2 = BlindingFactor::new(&mut rng);
    let com2 = params.commit(&msg2, bf2).unwrap();

    let proof_builder1 =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    // Pass in the commitment scalar of the first position onto the third position
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
    // Create a challenge from both transcripts
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

    // Verify both proofs
    assert!(proof1
        .verify_knowledge_of_opening_of_commitment(&params, com1, challenge)
        .unwrap());
    assert!(proof2
        .verify_knowledge_of_opening_of_commitment(&params, com2, challenge)
        .unwrap());
    // Verify linear equation
    assert_eq!(
        proof1.conjunction_response_scalars()[0],
        proof2.conjunction_response_scalars()[2]
    );
    // Verify the above was not an accident
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
