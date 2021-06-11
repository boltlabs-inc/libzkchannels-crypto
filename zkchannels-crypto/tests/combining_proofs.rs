use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::SeedableRng;
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    pointcheval_sanders::KeyPair,
    proofs::{ChallengeBuilder, CommitmentProofBuilder, SignatureProofBuilder},
    BlindingFactor, Message,
};

// Seeded rng for replicable tests.
fn rng() -> (impl rand::CryptoRng + rand::RngCore) {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[test]
/// Prove knowledge of a signature and knowledge of opening of a commitment that are on the same
/// message. This test constructs the signataure proof first.
fn signature_commitment_proof_linear_relation() {
    let mut rng = rng();
    // Generate message.
    let msg = Message::<3>::random(&mut rng);

    // Form signature on message.
    let kp = KeyPair::<3>::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Form commitment on message.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Construct proof - commitment phase.
    // Use matching commitment scalars for each message item.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        kp.public_key(),
    );
    let ccs = sig_proof_builder.conjunction_commitment_scalars();
    let com_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        &[Some(ccs[0]), Some(ccs[1]), Some(ccs[2])],
        &params,
    );

    // Form challenge from both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&sig_proof_builder)
        .with(&com_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let sig_proof = sig_proof_builder.generate_proof_response(challenge);
    let com_proof = com_proof_builder.generate_proof_response(&msg, bf, challenge);

    // Verify commitment proof is valid.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, com, challenge));
    // Verify signature proof is valid.
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), challenge));
    // Verify they are on the same message - response scalars must match.
    assert_eq!(
        com_proof.conjunction_response_scalars(),
        sig_proof.conjunction_response_scalars()
    );
}

#[test]
/// Prove knowledge of a signature and knowledge of opening of a commitment that are on the same
/// message. This test constructs the commitment proof first.
fn commitment_signature_proof_linear_relation() {
    let mut rng = rng();
    // Generate message.
    let msg = Message::<3>::random(&mut rng);
    // Form signature on message
    let kp = KeyPair::<3>::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Form commitment to message.
    let params = PedersenParameters::<G1Projective, 3>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Construct proof - commitment phase.
    // Use matching commitment scalars for each message item.
    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 3], &params);
    let ccs = com_proof_builder.conjunction_commitment_scalars();
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[Some(ccs[0]), Some(ccs[1]), Some(ccs[2])],
        kp.public_key(),
    );

    // Form challenge from both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&com_proof_builder)
        .with(&sig_proof_builder)
        .finish();

    // Complete proofs.
    let sig_proof = sig_proof_builder.generate_proof_response(challenge);
    let com_proof = com_proof_builder.generate_proof_response(&msg, bf, challenge);

    // Commitment proof must be valid.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, com, challenge));
    // Signature proof must be valid.
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), challenge));
    // Proofs must be on the same message - e.g. have matching response scalars.
    assert_eq!(
        com_proof.conjunction_response_scalars(),
        sig_proof.conjunction_response_scalars()
    );
}

#[test]
/// Prove knowledge of a signature and of opening of a commitment that have a linear relationship
/// with each other and a public value:
/// Sig( a ); Com( a + public_value )
fn commitment_signature_proof_linear_relation_public_addition() {
    let mut rng = rng();
    // Form message [a]; [a + public_value]
    let public_value = Scalar::random(&mut rng);
    let msg = Message::<1>::random(&mut rng);
    let msg2 = Message::new([msg[0] + public_value]);

    // Sign [a].
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Commit to [a + public_value].
    let params = PedersenParameters::<G1Projective, 1>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg2, bf);

    // Proof commitment phase: use the same commitment scalar for both messages.
    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; 1], &params);
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[Some(com_proof_builder.conjunction_commitment_scalars()[0])],
        kp.public_key(),
    );

    // Form challenge, integrating both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&sig_proof_builder)
        .with(&com_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let sig_proof = sig_proof_builder.generate_proof_response(challenge);
    let com_proof = com_proof_builder.generate_proof_response(&msg2, bf, challenge);

    // Both proofs must verify.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, com, challenge));
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), challenge));
    // The response scalars must have the expected relationship.
    assert_eq!(
        com_proof.conjunction_response_scalars()[0],
        sig_proof.conjunction_response_scalars()[0] + challenge.to_scalar() * public_value
    );
}
