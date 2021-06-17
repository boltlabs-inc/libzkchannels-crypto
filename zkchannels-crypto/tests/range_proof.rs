use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::SeedableRng;
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    pointcheval_sanders::KeyPair,
    proofs::{
        ChallengeBuilder, CommitmentProofBuilder, RangeProofBuilder, RangeProofParameters,
        SignatureProofBuilder,
    },
    BlindingFactor, Message,
};

// Seeded rng for replicable tests.
fn rng() -> (impl rand::CryptoRng + rand::RngCore) {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[test]
fn range_proof_with_commitment_verifies() {
    let mut rng = rng();
    let range_tested_value: u32 = 10;
    // Generate message and form commitment.
    let msg = Message::new([
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Proof commitment phase: prepare range proof on the value and use the resulting commitment scalar in the commitment proof.
    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[Some(range_proof_builder.commitment_scalar()), None, None],
        &params,
    );

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_proof_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder.generate_proof_response(challenge);
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_proof)
        .with(&proof)
        .finish();
    // Verify range proof is valid with respect to the corresponding response scalar from the commitment proof.
    assert!(range_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[0]
    ));
    // Verify commitment proof is valid.
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));

    // Verify that the range proof *doesn't* pass with a different response scalar.
    assert!(!range_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[2]
    ));
}

#[test]
fn range_proof_with_signature_verifies() {
    let mut rng = rng();

    // Generate message and signature.
    let range_tested_value: u32 = 10;
    let msg = Message::new([
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Proof commitment phase. Form range proof on element and use resulting commitment scalar in
    // signature proof.
    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[Some(range_proof_builder.commitment_scalar()), None, None],
        kp.public_key(),
    );

    // Form challenge with both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_proof_builder)
        .with(&sig_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder.generate_proof_response(challenge);
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_proof)
        .with(&proof)
        .finish();
    // Signature proof must be valid.
    assert!(proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    // Range proof must be valid with respect to the corresponding response scalar from the signature proof.
    assert!(range_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[0]
    ));

    // Range proof must *not* pass with any other response scalar.
    assert!(!range_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[2]
    ));
}

#[test]
#[should_panic(expected = "OutsideRange")]
fn range_proof_no_negative_value() {
    let mut rng = rng();
    let rp_params = RangeProofParameters::new(&mut rng);
    // Construct proof on a negative number (e.g. outside the range (0, 2^63)).
    let _range_proof_builder =
        RangeProofBuilder::generate_proof_commitments(-10, &rp_params, &mut rng).unwrap();
}

#[test]
#[should_panic(expected = "OutsideRange")]
fn range_proof_test_upper_bound() {
    let mut rng = rng();
    let rp_params = RangeProofParameters::new(&mut rng);

    // Test value is 2^63. This will wrap around when we convert it to an i64.
    let too_large_value = i64::MAX as u64 + 1;

    let _ =
        RangeProofBuilder::generate_proof_commitments(too_large_value as i64, &rp_params, &mut rng)
            .unwrap();
}

#[test]
fn range_proof_test_extremes() {
    let mut rng = rng();

    // Form commitment to (0, 2^63 - 1).
    let params = PedersenParameters::<G1Projective, 2>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let msg = Message::new([Scalar::from(0), Scalar::from((i64::MAX) as u64)]);
    let com = params.commit(&msg, bf);

    // Proof commitment phase: build commitment proof with range proof
    let rp_params = RangeProofParameters::new(&mut rng);
    let zero_builder =
        RangeProofBuilder::generate_proof_commitments(0, &rp_params, &mut rng).unwrap();
    let max_builder =
        RangeProofBuilder::generate_proof_commitments(i64::MAX, &rp_params, &mut rng).unwrap();
    let com_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[
            Some(zero_builder.commitment_scalar()),
            Some(max_builder.commitment_scalar()),
        ],
        &params,
    );

    let challenge = ChallengeBuilder::new()
        .with(&com_builder)
        .with(&zero_builder)
        .with(&max_builder)
        .finish();

    let zero_proof = zero_builder.generate_proof_response(challenge);
    let max_proof = max_builder.generate_proof_response(challenge);
    let com_proof = com_builder.generate_proof_response(&msg, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&com_proof)
        .with(&zero_proof)
        .with(&max_proof)
        .finish();
    // Verify that all proofs are valid.
    let zero_verifies = zero_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        com_proof.conjunction_response_scalars()[0],
    );
    let max_verifies = max_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        com_proof.conjunction_response_scalars()[1],
    );
    let com_verifies =
        com_proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge);

    assert!(zero_verifies && max_verifies && com_verifies);
}

#[test]
fn range_proof_fails_with_wrong_input() {
    let mut rng = rng();

    // Generate a value to range-test and a *random* (unrelated) message.
    let range_tested_value: u32 = 10;
    let msg = Message::new([
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    assert_ne!(
        Scalar::from(u64::from(range_tested_value)),
        msg[0],
        "unfortunate RNG seed"
    );

    // Form commitment to message
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Proof commitment phase: prepare range proof on the value; use the resulting commitment scalar in the commitment proof.
    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[Some(range_proof_builder.commitment_scalar()), None, None],
        &params,
    );

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_proof_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder.generate_proof_response(challenge);
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_proof)
        .with(&proof)
        .finish();
    // Verify commitment proof is valid.
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));

    // Failure expected: verify range proof is *not* valid with respect to the response scalar
    // from the commitment proof.
    assert!(!range_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[0]
    ));
}

#[test]
fn range_proof_fails_if_unlinked() {
    let mut rng = rng();

    // Generate message.
    let range_tested_value: u32 = 10;
    let msg = Message::new([
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    // Form commitment to message.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Proof commitment phase: prepare range proof on the value.
    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    // Failure case: *don't* use the range commitment scalar in the commitment proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None, None, None], &params);

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_proof_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder.generate_proof_response(challenge);
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_proof)
        .with(&proof)
        .finish();
    // Commitment proof should still verify.
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));
    // Range proof should fail, since the commitment proof isn't built correctly w.r.t it.
    let range_value_response_scalar = proof.conjunction_response_scalars()[0];
    assert!(!range_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        range_value_response_scalar
    ));
}

#[test]
fn range_proof_value_revealed() {
    let mut rng = rng();

    let range_tested_value: u32 = 10;
    // Generate message.
    let msg = Message::new([
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);

    // Form commitment to message
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Proof commitment phase: prepare range proof on the value; use the resulting commitment scalar in the commitment proof.
    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let range_value_commitment_scalar = range_proof_builder.commitment_scalar();
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[Some(range_value_commitment_scalar), None, None],
        &params,
    );

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_proof_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder.generate_proof_response(challenge);
    let proof = proof_builder.generate_proof_response(&msg, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_proof)
        .with(&proof)
        .finish();
    // Range proof and commitment proof must verify.
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));
    let range_value_response_scalar = proof.conjunction_response_scalars()[0];
    assert!(range_proof.verify_range_proof(
        &rp_params,
        verif_challenge,
        range_value_response_scalar
    ));
    // Revealed value should match partial opening.
    assert_eq!(
        range_value_response_scalar,
        verif_challenge.to_scalar() * msg[0] + range_value_commitment_scalar
    );
}
