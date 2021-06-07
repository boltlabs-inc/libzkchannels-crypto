use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::thread_rng;
use zkchannels_crypto::challenge::ChallengeBuilder;
use zkchannels_crypto::commitment_proof::CommitmentProofBuilder;
use zkchannels_crypto::message::{BlindingFactor, Message};
use zkchannels_crypto::pedersen_commitments::PedersenParameters;
use zkchannels_crypto::ps_keys::KeyPair;
use zkchannels_crypto::ps_signatures::Signer;
use zkchannels_crypto::range_proof::{RangeProofBuilder, RangeProofParameters};
use zkchannels_crypto::signature_proof::SignatureProofBuilder;

#[test]
fn range_proof_with_commitment_verifies() {
    let mut rng = thread_rng();
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
    let mut rng = thread_rng();
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
    let mut rng = thread_rng();
    let rp_params = RangeProofParameters::new(&mut rng);
    // Construct proof on a negative number (e.g. outside the range (0, 2^63)).
    let _range_proof_builder =
        RangeProofBuilder::generate_proof_commitments(-10, &rp_params, &mut rng).unwrap();
}
