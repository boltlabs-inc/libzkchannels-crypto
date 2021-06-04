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
