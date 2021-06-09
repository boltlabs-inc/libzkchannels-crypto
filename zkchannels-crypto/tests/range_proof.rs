use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::SeedableRng;
use zkchannels_crypto::{
    challenge::ChallengeBuilder,
    commitment_proof::CommitmentProofBuilder,
    message::{BlindingFactor, Message},
    pedersen_commitments::PedersenParameters,
    ps_keys::KeyPair,
    ps_signatures::Signer,
    range_proof::{RangeProofBuilder, RangeProofParameters},
    signature_proof::SignatureProofBuilder,
    Rng,
};

// Seeded rng for replicable tests.
fn rng() -> impl Rng {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[test]
fn range_proof_with_commitment_verifies() {
    let mut rng = rng();
    let length = 3;
    let range_tested_value: u32 = 10;
    // Generate message and form commitment.
    let msg = Message::new(vec![
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

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
        &[Some(range_proof_builder.commitment_scalar), None, None],
        &params,
    )
    .unwrap();

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with_range_proof(&range_proof_builder)
        .with_commitment_proof(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    // Verify range proof is valid with respect to the corresponding response scalar from the commitment proof.
    assert!(range_proof
        .verify_range_proof(
            &rp_params,
            challenge,
            proof.conjunction_response_scalars()[0]
        )
        .unwrap());
    // Verify commitment proof is valid.
    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());

    // Verify that the range proof *doesn't* pass with a different response scalar.
    assert!(!range_proof
        .verify_range_proof(
            &rp_params,
            challenge,
            proof.conjunction_response_scalars()[2]
        )
        .unwrap());
}

#[test]
fn range_proof_with_signature_verifies() {
    let mut rng = rng();
    let length = 3;

    // Generate message and signature.
    let range_tested_value: u32 = 10;
    let msg = Message::new(vec![
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    let kp = KeyPair::new(length, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

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
        &[Some(range_proof_builder.commitment_scalar), None, None],
        kp.public_key(),
    )
    .unwrap();

    // Form challenge with both proofs.
    let challenge = ChallengeBuilder::new()
        .with_range_proof(&range_proof_builder)
        .with_signature_proof(&sig_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let proof = sig_proof_builder
        .generate_proof_response(challenge)
        .unwrap();

    // Signature proof must be valid.
    assert!(proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    // Range proof must be valid with respect to the corresponding response scalar from the signature proof.
    assert!(range_proof
        .verify_range_proof(
            &rp_params,
            challenge,
            proof.conjunction_response_scalars()[0]
        )
        .unwrap());

    // Range proof must *not* pass with any other response scalar.
    assert!(!range_proof
        .verify_range_proof(
            &rp_params,
            challenge,
            proof.conjunction_response_scalars()[2]
        )
        .unwrap());
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
fn range_proof_fails_with_wrong_input() {
    let mut rng = rng();
    let length = 3;
    // Generate a value to range-test and a *random* (unrelated) message.
    let range_tested_value: u32 = 10;
    let msg = Message::new(vec![
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    assert_ne!(
        Scalar::from(u64::from(range_tested_value)),
        msg[0],
        "weird rng behavior."
    );

    // Form commitment to message
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

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
        &[Some(range_proof_builder.commitment_scalar), None, None],
        &params,
    )
    .unwrap();

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with_range_proof(&range_proof_builder)
        .with_commitment_proof(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    // Verify commitment proof is valid.
    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());

    // Failure expected: verify range proof is *not* valid with respect to the response scalar
    // from the commitment proof.
    assert!(!range_proof
        .verify_range_proof(
            &rp_params,
            challenge,
            proof.conjunction_response_scalars()[0]
        )
        .unwrap());
}

#[test]
fn range_proof_fails_if_unlinked() {
    let mut rng = rng();
    let length = 3;
    // Generate message.
    let range_tested_value: u32 = 10;
    let msg = Message::new(vec![
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);
    // Form commitment to message.
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

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
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None, None, None], &params)
            .unwrap();

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with_range_proof(&range_proof_builder)
        .with_commitment_proof(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    // Commitment proof should still verify.
    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
    // Range proof should fail, since the commitment proof isn't built correctly w.r.t it.
    let range_value_response_scalar = proof.conjunction_response_scalars()[0];
    assert!(!range_proof
        .verify_range_proof(&rp_params, challenge, range_value_response_scalar)
        .unwrap());
}

#[test]
fn range_proof_value_revealed() {
    let mut rng = rng();
    let length = 3;
    let range_tested_value: u32 = 10;
    // Generate message.
    let msg = Message::new(vec![
        Scalar::from(u64::from(range_tested_value)),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ]);

    // Form commitment to message
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    // Proof commitment phase: prepare range proof on the value; use the resulting commitment scalar in the commitment proof.
    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let range_value_commitment_scalar = range_proof_builder.commitment_scalar;
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[Some(range_value_commitment_scalar), None, None],
        &params,
    )
    .unwrap();

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with_range_proof(&range_proof_builder)
        .with_commitment_proof(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_proof = range_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    // Range proof and commitment proof must verify.
    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
    let range_value_response_scalar = proof.conjunction_response_scalars()[0];
    assert!(range_proof
        .verify_range_proof(&rp_params, challenge, range_value_response_scalar)
        .unwrap());
    // Revealed value should match partial opening.
    assert_eq!(
        range_value_response_scalar,
        challenge.0 * msg[0] + range_value_commitment_scalar
    );
}
