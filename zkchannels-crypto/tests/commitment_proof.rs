use bls12_381::*;
use ff::Field;
use rand::{Rng, SeedableRng};
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    proofs::{ChallengeBuilder, CommitmentProofBuilder},
    BlindingFactor, Message,
};

// Seeded rng for replicable tests.
fn rng() -> (impl rand::CryptoRng + rand::RngCore) {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[test]
fn commitment_proof_verifies() {
    let mut rng = rng();

    // Generate message.
    let msg = Message::<3>::random(&mut rng);

    // Form commmitment.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Build proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params);
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    // Proof must verify with the original commit.
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof.scalar_commitment())
        .finish();
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));
}

#[test]
fn commitment_proof_fails_on_wrong_commit() {
    let mut rng = rng();

    // Generate message.
    let msg = Message::<3>::random(&mut rng);

    // Form the "correct" commmitment.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Build proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params);
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    // Proof must not verify on a commitment with the wrong blinding factor.
    let bad_bf = BlindingFactor::new(&mut rng);
    let bad_bf_com = params.commit(&msg, bad_bf);
    assert_ne!(
        com, bad_bf_com,
        "Unfortunate RNG seed: Accidentally generated matching messages."
    );
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof.scalar_commitment())
        .finish();
    assert!(
        !proof.verify_knowledge_of_opening_of_commitment(&params, bad_bf_com, verif_challenge),
        "Proof verified on commitment with wrong blinding factor."
    );

    // Proof must not verify on a commitment with the wrong parameters.
    let bad_params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bad_params_com = bad_params.commit(&msg, bf);
    assert_ne!(
        com, bad_params_com,
        "Unfortunate RNG seed: Accidentally generated matching messages."
    );
    assert!(
        !proof.verify_knowledge_of_opening_of_commitment(&params, bad_params_com, challenge),
        "Proof verified on commitment with wrong parameters."
    );

    // Proof must to verify on a commitment with the wrong message.
    let bad_msg = Message::<3>::random(&mut rng);
    assert_ne!(&*msg, &*bad_msg, "Accidentally generated matching messages");
    let bad_msg_com = params.commit(&bad_msg, bf);
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof.scalar_commitment())
        .finish();
    assert!(
        !proof.verify_knowledge_of_opening_of_commitment(&params, bad_msg_com, verif_challenge),
        "Proof verified on commitment with wrong message."
    );
}

#[test]
fn commitment_proof_fails_on_bad_response_phase() {
    let mut rng = rng();

    // Generate message.
    let msg = Message::<3>::random(&mut rng);

    // Form commmitment.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Start proof, making a copy for each version of this test.
    let proof_builder_for_msg =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params);
    let challenge = ChallengeBuilder::new()
        .with(&proof_builder_for_msg)
        .finish();
    let proof_builder_for_bf = proof_builder_for_msg.clone();

    // Run response phase with wrong message.
    let bad_msg = Message::<3>::random(&mut rng);
    assert_ne!(
        &*msg, &*bad_msg,
        "Accidentally generated matching messages."
    );
    let proof = proof_builder_for_msg.generate_proof_response(&bad_msg, bf, challenge);
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof.scalar_commitment())
        .finish();
    assert!(
        !proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge),
        "Proof verified with bad message in response phase."
    );

    // Run response phase with wrong blinding factor.
    let bad_bf = BlindingFactor::new(&mut rng);
    let bad_bf_proof = proof_builder_for_bf.generate_proof_response(&msg, bad_bf, challenge);
    assert!(
        !bad_bf_proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge),
        "Proof verified with bad blinding factor in response phase."
    );
}

#[test]
fn commitment_proof_fails_on_wrong_challenge() {
    let mut rng = rng();

    // Generate message.
    let msg = Message::<3>::random(&mut rng);

    // Form commmitment.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Build proof using normally-generated challenge.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params);
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    // Proof must *not* verify with the wrong challenge.
    let random_bytes = rng.gen::<[u8; 32]>();
    let bad_challenge = ChallengeBuilder::new().with_bytes(&random_bytes).finish();
    assert_ne!(
        bad_challenge.to_scalar(),
        challenge.to_scalar(),
        "Accidentally generated matching challenge."
    );
    assert!(!proof.verify_knowledge_of_opening_of_commitment(&params, com, bad_challenge));
}

#[test]
fn commitment_proof_with_linear_relation() {
    let mut rng = rng();

    // Construct messages of the form [a, ., .]; [., ., a]
    // e.g. the last element of the second equals the first element of the first.
    let msg1 = Message::<3>::random(&mut rng);
    let msg2 = Message::new([Scalar::random(&mut rng), Scalar::random(&mut rng), msg1[0]]);

    // Construct commitments.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf1 = BlindingFactor::new(&mut rng);
    let com1 = params.commit(&msg1, bf1);
    let bf2 = BlindingFactor::new(&mut rng);
    let com2 = params.commit(&msg2, bf2);

    // Construct proofs - commitment phase.
    let proof_builder1 =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params);
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
    );

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with(&proof_builder1)
        .with(&proof_builder2)
        .finish();

    // Complete proofs - response phase.
    let proof1 = proof_builder1.generate_proof_response(&msg1, bf1, challenge);
    let proof2 = proof_builder2.generate_proof_response(&msg2, bf2, challenge);

    // Verify both proofs.
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof1.scalar_commitment())
        .with(&proof2.scalar_commitment())
        .finish();
    assert!(proof1.verify_knowledge_of_opening_of_commitment(&params, com1, verif_challenge));
    assert!(proof2.verify_knowledge_of_opening_of_commitment(&params, com2, verif_challenge));

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

    // Construct message and commitment.
    let msg = Message::<3>::random(&mut rng);
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Construct proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params);
    // Save commitment scalars for public elements (in this case, all of them).
    let commitment_scalars = proof_builder.conjunction_commitment_scalars().to_vec();
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    // Verify underlying proof.
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof.scalar_commitment())
        .finish();
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));

    // Verify response scalars are correctly formed against the public msg.
    let response_scalars = proof.conjunction_response_scalars();
    assert_eq!(
        msg[0] * challenge.to_scalar() + commitment_scalars[0],
        response_scalars[0]
    );
    assert_eq!(
        msg[1] * challenge.to_scalar() + commitment_scalars[1],
        response_scalars[1]
    );
    assert_eq!(
        msg[2] * challenge.to_scalar() + commitment_scalars[2],
        response_scalars[2]
    );
}

#[test]
fn commitment_proof_with_linear_relation_public_addition() {
    let mut rng = rng();

    // Construct messages of the form [a]; [a + public_value]
    // e.g. the last element of the second equals the first element of the first.
    let public_value = Scalar::random(&mut rng);
    let msg_vec1 = [Scalar::random(&mut rng)];
    let msg_vec2 = [msg_vec1[0] + public_value];
    let msg1 = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);

    // Construct commitments.
    let params = PedersenParameters::<G1Projective, 1>::new(&mut rng);
    let bf1 = BlindingFactor::new(&mut rng);
    let com1 = params.commit(&msg1, bf1);
    let bf2 = BlindingFactor::new(&mut rng);
    let com2 = params.commit(&msg2, bf2);

    // Construct proof - commitment phase.
    let proof_builder1 =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 1], &params);
    // Commitment scalars for elements with linear relationships must match.
    let proof_builder2 = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[Some(proof_builder1.conjunction_commitment_scalars()[0])],
        &params,
    );

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with(&proof_builder1)
        .with(&proof_builder2)
        .finish();
    let proof1 = proof_builder1.generate_proof_response(&msg1, bf1, challenge);
    let proof2 = proof_builder2.generate_proof_response(&msg2, bf2, challenge);

    // Verify both proofs.
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof1.scalar_commitment())
        .with(&proof2.scalar_commitment())
        .finish();
    assert!(proof1.verify_knowledge_of_opening_of_commitment(&params, com1, verif_challenge));
    assert!(proof2.verify_knowledge_of_opening_of_commitment(&params, com2, verif_challenge));

    // Verify linear equation.
    assert_eq!(
        proof1.conjunction_response_scalars()[0] + verif_challenge.to_scalar() * public_value,
        proof2.conjunction_response_scalars()[0]
    );
}
