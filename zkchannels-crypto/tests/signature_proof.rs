use bls12_381::Scalar;
use ff::Field;
use rand::{Rng, SeedableRng};
use std::iter;
use zkchannels_crypto::{
    pointcheval_sanders::KeyPair,
    proofs::{ChallengeBuilder, SignatureProofBuilder},
    Message,
};

// Seeded rng for replicable tests.
fn rng() -> (impl rand::CryptoRng + rand::RngCore) {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[test]
fn signature_proof_verifies() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<3>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        kp.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    // Proof must verify with the same challenge and keypair.
    assert!(proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
}

#[test]
fn signature_proof_fails_with_wrong_message() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<3>::random(&mut rng);
    let bad_msg = Message::<3>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof with the wrong message.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        bad_msg,
        sig,
        &[None; 3],
        kp.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    // Proof must not verify.
    assert!(!proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
}

#[test]
fn signature_proof_fails_with_wrong_parameters_for_signature() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<3>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let bad_kp = KeyPair::new(&mut rng);

    // Sign message with the wrong parameters.
    let sig = bad_kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        kp.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    // Proof must not verify.
    assert!(!proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
}

#[test]
fn signature_proof_fails_with_wrong_parameters_for_proof() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<3>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let bad_kp = KeyPair::new(&mut rng);

    // Sign message.
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof with the wrong parameters.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        bad_kp.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    // Proof must not verify.
    assert!(!proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
}

#[test]
fn signature_proof_fails_with_wrong_parameters_for_verification() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<3>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let bad_kp = KeyPair::new(&mut rng);

    // Sign message.
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        kp.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    // Proof must not verify against the wrong parameters.
    assert!(!proof.verify_knowledge_of_signature(bad_kp.public_key(), verif_challenge));
}

#[test]
fn signature_proof_fails_with_wrong_challenge() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<3>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);

    // Sign message.
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        kp.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let random_challenge_seed = rng.gen::<[u8; 32]>();
    let bad_challenge = ChallengeBuilder::new()
        .with_bytes(&random_challenge_seed)
        .finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    // Proof must not verify against the wrong challenge.
    assert!(!proof.verify_knowledge_of_signature(kp.public_key(), bad_challenge));
}

#[test]
fn signature_proof_linear_relation() {
    let mut rng = rng();
    let length = 3;
    // Construct messages of the form [a, ., .]; [., ., a]
    // e.g. where the first and last elements of the two messages must match.
    let msg_vec1 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length)
        .collect::<Vec<Scalar>>();
    let mut msg_vec2 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(length - 1)
        .collect::<Vec<Scalar>>();
    msg_vec2.push(msg_vec1[0]);
    let msg = Message::<3>::random(&mut rng);
    let msg2 = Message::new([Scalar::random(&mut rng), Scalar::random(&mut rng), msg[0]]);

    // Sign the messages
    let kp = KeyPair::new(&mut rng);
    let sig1 = kp.sign(&mut rng, &msg);
    let sig2 = kp.sign(&mut rng, &msg2);

    // Form proofs - commitment phase. The commitment scalars for the matching elements must match.
    let sig_proof_builder1 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig1,
        &[None; 3],
        kp.public_key(),
    );
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
    );

    // Form challenge from both proof transcripts.
    let challenge = ChallengeBuilder::new()
        .with(&sig_proof_builder1)
        .with(&sig_proof_builder2)
        .finish();

    // Complete proofs - response phase.
    let proof1 = sig_proof_builder1.generate_proof_response(challenge);
    let proof2 = sig_proof_builder2.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof1).with(&proof2).finish();
    // Proofs must verify.
    assert!(proof1.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    assert!(proof2.verify_knowledge_of_signature(kp.public_key(), verif_challenge));

    // Response scalars for matching elements must match.
    assert_eq!(
        proof1.conjunction_response_scalars()[0],
        proof2.conjunction_response_scalars()[2]
    );

    // Response scalars for other elements should *not* match!
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

#[test]
fn signature_proof_public_value() {
    let mut rng = rng();

    // Form message and signature.
    let msg = Message::<3>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; 3],
        kp.public_key(),
    );
    // Save commitment scalars for publicly revealed values (in this case, all of them).
    let commitment_scalars = sig_proof_builder.conjunction_commitment_scalars().to_vec();
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    // Proof must verify.
    assert!(proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));

    // Verify response scalars are correctly formed w.r.t public message and revealed commitment scalars.
    let response_scalars = proof.conjunction_response_scalars();
    assert_eq!(
        msg[0] * verif_challenge.to_scalar() + commitment_scalars[0],
        response_scalars[0]
    );
    assert_eq!(
        msg[1] * verif_challenge.to_scalar() + commitment_scalars[1],
        response_scalars[1]
    );
    assert_eq!(
        msg[2] * verif_challenge.to_scalar() + commitment_scalars[2],
        response_scalars[2]
    );
}

#[test]
fn signature_proof_linear_relation_public_addition() {
    let mut rng = rng();
    // Create messages of the form [a], [a + public_value].
    let public_value = Scalar::random(&mut rng);
    let msg = Message::new([Scalar::random(&mut rng)]);
    let msg2 = Message::new([msg[0] + public_value]);

    // Form signatures on messages.
    let kp = KeyPair::new(&mut rng);
    let sig1 = kp.sign(&mut rng, &msg);
    let sig2 = kp.sign(&mut rng, &msg2);

    // Proof commitment phase: use matching commitment scalars for message values with linear relationship.
    let sig_proof_builder1 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig1,
        &[None; 1],
        kp.public_key(),
    );
    let sig_proof_builder2 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2,
        sig2,
        &[Some(sig_proof_builder1.conjunction_commitment_scalars()[0])],
        kp.public_key(),
    );

    // Construct challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&sig_proof_builder1)
        .with(&sig_proof_builder2)
        .finish();

    // Form proofs - response phase.
    let proof1 = sig_proof_builder1.generate_proof_response(challenge);
    let proof2 = sig_proof_builder2.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof1).with(&proof2).finish();
    // Both signature proofs must verify.
    assert!(proof1.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    assert!(proof2.verify_knowledge_of_signature(kp.public_key(), verif_challenge));

    // The expected linear relationship must hold for the response scalars.
    assert_eq!(
        proof1.conjunction_response_scalars()[0] + verif_challenge.to_scalar() * public_value,
        proof2.conjunction_response_scalars()[0]
    );
}
