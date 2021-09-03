mod test_utils;

use arrayvec::ArrayVec;
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::{CryptoRng, Rng, RngCore};
use std::iter;
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    pointcheval_sanders::KeyPair,
    proofs::{
        ChallengeBuilder, CommitmentProofBuilder, RangeConstraintBuilder,
        RangeConstraintParameters, SignatureProofBuilder,
    },
    Message,
};

#[test]
fn range_constraint_with_commitment_verifies() {
    run_range_constraint_with_commitment_verifies::<1>();
    run_range_constraint_with_commitment_verifies::<2>();
    run_range_constraint_with_commitment_verifies::<3>();
    run_range_constraint_with_commitment_verifies::<5>();
    run_range_constraint_with_commitment_verifies::<8>();
    run_range_constraint_with_commitment_verifies::<13>();
}

fn run_range_constraint_with_commitment_verifies<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();
    let (range_tested_value, pos, msg) = message_with_value_in_range(&mut rng, &mut real_rng);

    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Proof commitment phase: prepare range constraint on the value and use the resulting commitment scalar in the commitment proof.
    let rp_params = RangeConstraintParameters::new(&mut rng);
    let range_constraint_builder = RangeConstraintBuilder::generate_constraint_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[pos] = Some(range_constraint_builder.commitment_scalar());
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        &conjunction_commitment_scalars,
        &params,
    );

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_constraint_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_constraint = range_constraint_builder.generate_constraint_response(challenge);
    let proof = proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_constraint)
        .with(&proof)
        .finish();
    assert_eq!(challenge.to_scalar(), verif_challenge.to_scalar());
    // Verify range constraint is valid with respect to the corresponding response scalar from the commitment proof.
    assert!(range_constraint.verify_range_constraint(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[pos]
    ));
    // Verify commitment proof is valid.
    assert!(proof.verify_knowledge_of_opening(&params, verif_challenge));

    // Verify that the range constraint *doesn't* pass with a different response scalar.
    for i in 0..N {
        if i != pos {
            assert!(!range_constraint.verify_range_constraint(
                &rp_params,
                verif_challenge,
                proof.conjunction_response_scalars()[i]
            ));
        }
    }
}

#[test]
fn range_constraint_with_signature_verifies() {
    run_range_constraint_with_signature_verifies::<1>();
    run_range_constraint_with_signature_verifies::<2>();
    run_range_constraint_with_signature_verifies::<3>();
    run_range_constraint_with_signature_verifies::<5>();
    run_range_constraint_with_signature_verifies::<8>();
    run_range_constraint_with_signature_verifies::<13>();
}

fn run_range_constraint_with_signature_verifies<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Generate message and signature.
    let (range_tested_value, pos, msg) = message_with_value_in_range(&mut rng, &mut real_rng);

    let kp = KeyPair::new(&mut rng);
    let sig = msg.sign(&mut rng, &kp);

    // Proof commitment phase. Form range constraint on element and use resulting commitment scalar in
    // signature proof.
    let rp_params = RangeConstraintParameters::new(&mut rng);
    let range_constraint_builder = RangeConstraintBuilder::generate_constraint_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[pos] = Some(range_constraint_builder.commitment_scalar());
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &conjunction_commitment_scalars,
        kp.public_key(),
    );

    // Form challenge with both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_constraint_builder)
        .with(&sig_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_constraint = range_constraint_builder.generate_constraint_response(challenge);
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_constraint)
        .with(&proof)
        .finish();
    assert_eq!(challenge.to_scalar(), verif_challenge.to_scalar());
    // Signature proof must be valid.
    assert!(proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    // Range constraint must be valid with respect to the corresponding response scalar from the signature proof.
    assert!(range_constraint.verify_range_constraint(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[pos]
    ));

    // Range constraint must *not* pass with any other response scalar.
    for i in 0..N {
        if i != pos {
            assert!(!range_constraint.verify_range_constraint(
                &rp_params,
                verif_challenge,
                proof.conjunction_response_scalars()[i]
            ));
        }
    }
}

#[test]
#[should_panic(expected = "OutsideRange")]
fn range_constraint_no_negative_value() {
    let mut rng = test_utils::seeded_rng();
    let rp_params = RangeConstraintParameters::new(&mut rng);
    // Construct proof on a negative number (e.g. outside the range (0, 2^63)).
    let _range_constraint_builder =
        RangeConstraintBuilder::generate_constraint_commitments(-10, &rp_params, &mut rng).unwrap();
}

#[test]
#[should_panic(expected = "OutsideRange")]
fn range_constraint_test_upper_bound() {
    let mut rng = test_utils::seeded_rng();
    let rp_params = RangeConstraintParameters::new(&mut rng);

    // Test value is 2^63. This will wrap around when we convert it to an i64.
    let too_large_value = i64::MAX as u64 + 1;

    let _ = RangeConstraintBuilder::generate_constraint_commitments(
        too_large_value as i64,
        &rp_params,
        &mut rng,
    )
    .unwrap();
}

#[test]
fn range_constraint_test_extremes() {
    let mut rng = test_utils::seeded_rng();

    // Form commitment to (0, 2^63 - 1).
    let params = PedersenParameters::<G1Projective, 2>::new(&mut rng);
    let msg = Message::new([Scalar::from(0), Scalar::from((i64::MAX) as u64)]);

    // Proof commitment phase: build commitment proof with range constraint
    let rp_params = RangeConstraintParameters::new(&mut rng);
    let zero_builder =
        RangeConstraintBuilder::generate_constraint_commitments(0, &rp_params, &mut rng).unwrap();
    let max_builder =
        RangeConstraintBuilder::generate_constraint_commitments(i64::MAX, &rp_params, &mut rng)
            .unwrap();
    let com_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
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

    let zero_proof = zero_builder.generate_constraint_response(challenge);
    let max_proof = max_builder.generate_constraint_response(challenge);
    let com_proof = com_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&com_proof)
        .with(&zero_proof)
        .with(&max_proof)
        .finish();
    assert_eq!(challenge.to_scalar(), verif_challenge.to_scalar());
    // Verify that all proofs are valid.
    let zero_verifies = zero_proof.verify_range_constraint(
        &rp_params,
        verif_challenge,
        com_proof.conjunction_response_scalars()[0],
    );
    let max_verifies = max_proof.verify_range_constraint(
        &rp_params,
        verif_challenge,
        com_proof.conjunction_response_scalars()[1],
    );
    let com_verifies = com_proof.verify_knowledge_of_opening(&params, verif_challenge);

    assert!(zero_verifies && max_verifies && com_verifies);
}

#[test]
fn range_constraint_fails_with_wrong_input() {
    run_range_constraint_fails_with_wrong_input::<1>();
    run_range_constraint_fails_with_wrong_input::<2>();
    run_range_constraint_fails_with_wrong_input::<3>();
    run_range_constraint_fails_with_wrong_input::<5>();
    run_range_constraint_fails_with_wrong_input::<8>();
    run_range_constraint_fails_with_wrong_input::<13>();
}

fn run_range_constraint_fails_with_wrong_input<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Generate a value to range-test and a *random* (unrelated) message.
    let range_tested_value = rng.gen_range(0..i64::MAX) as u32;
    let msg = Message::<N>::random(&mut rng);
    let pos = real_rng.gen_range(0..N);
    assert_ne!(
        Scalar::from(u64::from(range_tested_value)),
        msg[pos],
        "unfortunate RNG seed"
    );

    // Form commitment to message
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Proof commitment phase: prepare range constraint on the value; use the resulting commitment scalar in the commitment proof.
    let rp_params = RangeConstraintParameters::new(&mut rng);
    let range_constraint_builder = RangeConstraintBuilder::generate_constraint_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[pos] = Some(range_constraint_builder.commitment_scalar());
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        &conjunction_commitment_scalars,
        &params,
    );

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_constraint_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_constraint = range_constraint_builder.generate_constraint_response(challenge);
    let proof = proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_constraint)
        .with(&proof)
        .finish();
    assert_eq!(challenge.to_scalar(), verif_challenge.to_scalar());
    // Verify commitment proof is valid.
    assert!(proof.verify_knowledge_of_opening(&params, verif_challenge));

    // Failure expected: verify range constraint is *not* valid with respect to the response scalar
    // from the commitment proof.
    assert!(!range_constraint.verify_range_constraint(
        &rp_params,
        verif_challenge,
        proof.conjunction_response_scalars()[pos]
    ));
}

#[test]
fn range_constraint_fails_if_unlinked() {
    run_range_constraint_fails_if_unlinked::<1>();
    run_range_constraint_fails_if_unlinked::<2>();
    run_range_constraint_fails_if_unlinked::<3>();
    run_range_constraint_fails_if_unlinked::<5>();
    run_range_constraint_fails_if_unlinked::<8>();
    run_range_constraint_fails_if_unlinked::<13>();
}

fn run_range_constraint_fails_if_unlinked<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Generate message.
    let (range_tested_value, pos, msg) = message_with_value_in_range(&mut rng, &mut real_rng);

    // Form commitment to message.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Proof commitment phase: prepare range constraint on the value.
    let rp_params = RangeConstraintParameters::new(&mut rng);
    let range_constraint_builder = RangeConstraintBuilder::generate_constraint_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    // Failure case: *don't* use the range commitment scalar in the commitment proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg, &[None; N], &params);

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_constraint_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_constraint = range_constraint_builder.generate_constraint_response(challenge);
    let proof = proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_constraint)
        .with(&proof)
        .finish();
    assert_eq!(challenge.to_scalar(), verif_challenge.to_scalar());
    // Commitment proof should still verify.
    assert!(proof.verify_knowledge_of_opening(&params, verif_challenge));
    // Range constraint should fail, since the commitment proof isn't built correctly w.r.t it.
    let range_value_response_scalar = proof.conjunction_response_scalars()[pos];
    assert!(!range_constraint.verify_range_constraint(
        &rp_params,
        verif_challenge,
        range_value_response_scalar
    ));
}

#[test]
fn range_constraint_value_revealed() {
    run_range_constraint_value_revealed::<1>();
    run_range_constraint_value_revealed::<2>();
    run_range_constraint_value_revealed::<3>();
    run_range_constraint_value_revealed::<5>();
    run_range_constraint_value_revealed::<8>();
    run_range_constraint_value_revealed::<13>();
}

fn run_range_constraint_value_revealed<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Generate message.
    let (range_tested_value, pos, msg) = message_with_value_in_range(&mut rng, &mut real_rng);

    // Form commitment to message
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Proof commitment phase: prepare range constraint on the value; use the resulting commitment scalar in the commitment proof.
    let rp_params = RangeConstraintParameters::new(&mut rng);
    let range_constraint_builder = RangeConstraintBuilder::generate_constraint_commitments(
        range_tested_value.into(),
        &rp_params,
        &mut rng,
    )
    .unwrap();
    let range_value_commitment_scalar = range_constraint_builder.commitment_scalar();
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[pos] = Some(range_value_commitment_scalar);
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        &conjunction_commitment_scalars,
        &params,
    );

    // Form challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&range_constraint_builder)
        .with(&proof_builder)
        .finish();

    // Complete proofs - response phase.
    let range_constraint = range_constraint_builder.generate_constraint_response(challenge);
    let proof = proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&range_constraint)
        .with(&proof)
        .finish();
    assert_eq!(challenge.to_scalar(), verif_challenge.to_scalar());
    // Range constraint and commitment proof must verify.
    assert!(proof.verify_knowledge_of_opening(&params, verif_challenge));
    let range_value_response_scalar = proof.conjunction_response_scalars()[pos];
    assert!(range_constraint.verify_range_constraint(
        &rp_params,
        verif_challenge,
        range_value_response_scalar
    ));
    // Revealed value should match partial opening.
    assert_eq!(
        range_value_response_scalar,
        verif_challenge.to_scalar() * msg[pos] + range_value_commitment_scalar
    );
}

fn message_with_value_in_range<const N: usize>(
    mut rng: &mut (impl CryptoRng + RngCore),
    real_rng: &mut (impl CryptoRng + RngCore),
) -> (u32, usize, Message<N>) {
    let range_tested_value = real_rng.gen_range(0..i64::MAX) as u32;
    // Generate message and form commitment.
    let mut msg_vec = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    let pos = real_rng.gen_range(0..N);
    msg_vec[pos] = Scalar::from(u64::from(range_tested_value));
    let msg = Message::new(msg_vec);
    (range_tested_value, pos, msg)
}
