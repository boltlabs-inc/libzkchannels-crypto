use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::thread_rng;
use std::iter;
use zkchannels_crypto::challenge::ChallengeBuilder;
use zkchannels_crypto::commitment_proof::CommitmentProofBuilder;
use zkchannels_crypto::message::{BlindingFactor, Message};
use zkchannels_crypto::pedersen_commitments::PedersenParameters;
use zkchannels_crypto::ps_keys::KeyPair;
use zkchannels_crypto::ps_signatures::Signer;
use zkchannels_crypto::signature_proof::SignatureProofBuilder;
use zkchannels_crypto::Rng;

fn rng() -> impl Rng {
    thread_rng()
}

#[test]
fn signature_commitment_proof_linear_relation() {
    let mut rng = rng();
    let length = 3;
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let kp = KeyPair::new(length, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        sig,
        &[None; 3],
        kp.public_key(),
    )
    .unwrap();
    let com_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &sig_proof_builder
            .conjunction_commitment_scalars()
            .iter()
            .map(|scalar| Some(*scalar))
            .collect::<Vec<Option<Scalar>>>()[..],
        &params,
    )
    .unwrap();
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder)
        .with_commitment_proof(&com_proof_builder)
        .finish();
    let sig_proof = sig_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let com_proof = com_proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    assert!(com_proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
    assert!(sig_proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert_eq!(
        com_proof.conjunction_response_scalars(),
        sig_proof.conjunction_response_scalars()
    );
}

#[test]
fn commitment_signature_proof_linear_relation() {
    let mut rng = rng();
    let length = 3;
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let kp = KeyPair::new(length, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        sig,
        &com_proof_builder
            .conjunction_commitment_scalars()
            .iter()
            .map(|scalar| Some(*scalar))
            .collect::<Vec<Option<Scalar>>>()[..],
        kp.public_key(),
    )
    .unwrap();
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder)
        .with_commitment_proof(&com_proof_builder)
        .finish();
    let sig_proof = sig_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let com_proof = com_proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    assert!(com_proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
    assert!(sig_proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert_eq!(
        com_proof.conjunction_response_scalars(),
        sig_proof.conjunction_response_scalars()
    );
}

#[test]
fn commitment_signature_proof_linear_relation_public_addition() {
    let mut rng = rng();
    let public_value = Scalar::random(&mut rng);
    let msg = Message::new(vec![Scalar::random(&mut rng)]);
    let msg2 = Message::new(vec![msg[0] + public_value]);
    let kp = KeyPair::new(1, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

    let params = PedersenParameters::<G1Projective>::new(1, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg2, bf).unwrap();

    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 1], &params).unwrap();
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &com_proof_builder
            .conjunction_commitment_scalars()
            .iter()
            .map(|scalar| Some(*scalar))
            .collect::<Vec<Option<Scalar>>>()[..],
        kp.public_key(),
    )
    .unwrap();
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder)
        .with_commitment_proof(&com_proof_builder)
        .finish();
    let sig_proof = sig_proof_builder
        .generate_proof_response(challenge)
        .unwrap();
    let com_proof = com_proof_builder
        .generate_proof_response(&msg2, bf, challenge)
        .unwrap();

    assert!(com_proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
    assert!(sig_proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert_eq!(
        com_proof.conjunction_response_scalars()[0] - challenge.0 * public_value,
        sig_proof.conjunction_response_scalars()[0]
    );
}
