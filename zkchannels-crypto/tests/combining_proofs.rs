use zkchannels_crypto::Rng;
use zkchannels_crypto::message::{Message, BlindingFactor};
use bls12_381::{Scalar, G1Projective};
use zkchannels_crypto::ps_keys::KeyPair;
use ff::Field;
use std::iter;
use zkchannels_crypto::ps_signatures::Signer;
use zkchannels_crypto::signature_proof::SignatureProofBuilder;
use zkchannels_crypto::challenge::ChallengeBuilder;
use zkchannels_crypto::pedersen_commitments::PedersenParameters;
use zkchannels_crypto::commitment_proof::CommitmentProofBuilder;

fn rng() -> impl Rng {
    use rand::SeedableRng;
    rand::rngs::StdRng::from_seed(*b"DON'T USE THIS FOR ANYTHING REAL")
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
    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &sig_proof_builder.conjunction_commitment_scalars().iter().map(|scalar| Some(*scalar)).collect::<Vec<Option<Scalar>>>()[..], &params).unwrap();
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
    assert_eq!(com_proof.conjunction_response_scalars(), sig_proof.conjunction_response_scalars());
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
        &com_proof_builder.conjunction_commitment_scalars().iter().map(|scalar| Some(*scalar)).collect::<Vec<Option<Scalar>>>()[..],
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
    assert_eq!(com_proof.conjunction_response_scalars(), sig_proof.conjunction_response_scalars());
}
