use zkchannels_crypto::message::{Message, BlindingFactor};
use bls12_381::{Scalar, G1Projective};
use zkchannels_crypto::pedersen_commitments::PedersenParameters;
use ff::Field;
use zkchannels_crypto::commitment_proof::CommitmentProofBuilder;
use zkchannels_crypto::challenge::ChallengeBuilder;
use rand::thread_rng;
use zkchannels_crypto::range_proof::{RangeProofBuilder, RangeProofParameters};
use zkchannels_crypto::ps_keys::KeyPair;
use zkchannels_crypto::signature_proof::SignatureProofBuilder;
use zkchannels_crypto::ps_signatures::Signer;

#[test]
fn range_proof_with_commitment_verifies() {
    let mut rng = thread_rng();
    let length = 3;
    let msg = Message::new(
        vec![Scalar::from(10), Scalar::random(&mut rng), Scalar::random(&mut rng)],
    );
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(10, &rp_params, &mut rng).unwrap();
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[Some(range_proof_builder.commitment_scalar), None, None], &params).unwrap();
    let challenge = ChallengeBuilder::new()
        .with_range_proof(&range_proof_builder)
        .with_commitment_proof(&proof_builder)
        .finish();
    let range_proof = range_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    assert!(range_proof.verify_range_proof(&rp_params, challenge, proof.conjunction_response_scalars()[0]).unwrap());
    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
}

#[test]
fn range_proof_with_signature_verifies() {
    let mut rng = thread_rng();
    let length = 3;
    let msg = Message::new(
        vec![Scalar::from(10), Scalar::random(&mut rng), Scalar::random(&mut rng)],
    );
    let kp = KeyPair::new(length, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

    let rp_params = RangeProofParameters::new(&mut rng);
    let range_proof_builder = RangeProofBuilder::generate_proof_commitments(10, &rp_params, &mut rng).unwrap();
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[Some(range_proof_builder.commitment_scalar), None, None],
        kp.public_key(),
    )
        .unwrap();
    let challenge = ChallengeBuilder::new()
        .with_range_proof(&range_proof_builder)
        .with_signature_proof(&sig_proof_builder)
        .finish();
    let range_proof = range_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let proof = sig_proof_builder
        .generate_proof_response(challenge)
        .unwrap();

    assert!(proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert!(range_proof.verify_range_proof(&rp_params, challenge, proof.conjunction_response_scalars()[0]).unwrap());
}

#[test]
#[should_panic(expected="OutsideRange")]
fn range_proof_no_negative_value() {
    let mut rng = thread_rng();
    let rp_params = RangeProofParameters::new(&mut rng);
    let _range_proof_builder = RangeProofBuilder::generate_proof_commitments(-10, &rp_params, &mut rng).unwrap();
}