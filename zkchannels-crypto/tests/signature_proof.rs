use bls12_381::Scalar;
use ff::Field;
use std::iter;
use zkchannels_crypto::challenge::ChallengeBuilder;
use zkchannels_crypto::message::Message;
use zkchannels_crypto::ps_keys::KeyPair;
use zkchannels_crypto::ps_signatures::Signer;
use zkchannels_crypto::signature_proof::SignatureProofBuilder;
use zkchannels_crypto::Rng;

fn rng() -> impl Rng {
    use rand::SeedableRng;
    rand::rngs::StdRng::from_seed(*b"DON'T USE THIS FOR ANYTHING REAL")
}

#[test]
fn signature_proof_verifies() {
    let mut rng = rng();
    let length = 3;
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let kp = KeyPair::new(length, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        kp.public_key(),
    )
    .unwrap();
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder)
        .finish();
    let proof = sig_proof_builder
        .generate_proof_response(challenge)
        .unwrap();

    assert!(proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
}

#[test]
fn signature_linear_relation() {
    let mut rng = rng();
    let length = 3;
    let msg_vec1 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length)
        .collect::<Vec<Scalar>>();
    let mut msg_vec2 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length - 1)
        .collect::<Vec<Scalar>>();
    msg_vec2.push(msg_vec1[0]);
    let msg = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);
    let kp = KeyPair::new(length, &mut rng);
    let sig1 = kp.try_sign(&mut rng, &msg).unwrap();
    let sig2 = kp.try_sign(&mut rng, &msg2).unwrap();

    let sig_proof_builder1 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig1,
        &[None; 3],
        kp.public_key(),
    )
    .unwrap();
    let sig_proof_builder2 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2,
        sig2,
        &[
            None,
            None,
            Some(sig_proof_builder1.conjunction_commitment_scalars()[0]),
        ],
        kp.public_key(),
    )
    .unwrap();
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder1)
        .with_signature_proof(&sig_proof_builder2)
        .finish();
    let proof1 = sig_proof_builder1
        .generate_proof_response(challenge)
        .unwrap();
    let proof2 = sig_proof_builder2
        .generate_proof_response(challenge)
        .unwrap();

    assert!(proof1
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert!(proof2
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert_eq!(
        proof1.conjunction_response_scalars()[0],
        proof2.conjunction_response_scalars()[2]
    );
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
