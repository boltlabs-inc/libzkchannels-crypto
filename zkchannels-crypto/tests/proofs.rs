use bls12_381::*;
use ff::Field;
use std::iter;
use zkchannels_crypto::{
    challenge::ChallengeBuilder,
    commitment_proof::CommitmentProofBuilder,
    message::{BlindingFactor, Message},
    pedersen_commitments::PedersenParameters,
    Rng,
};

fn rng() -> impl Rng {
    use rand::SeedableRng;
    rand::rngs::StdRng::from_seed(*b"DON'T USE THIS FOR ANYTHING REAL")
}

#[test]
fn commitment_proof_verifies() {
    let mut rng = rng();
    let length = 3;
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let params = PedersenParameters::<G1Projective>::new(length, &mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf).unwrap();

    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params).unwrap();
    let challenge = ChallengeBuilder::new()
        .with_commitment_proof(&proof_builder)
        .finish();
    let proof = proof_builder
        .generate_proof_response(&msg, bf, challenge)
        .unwrap();

    assert!(proof
        .verify_knowledge_of_opening_of_commitment(&params, com, challenge)
        .unwrap());
}
