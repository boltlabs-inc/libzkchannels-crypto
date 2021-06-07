use bls12_381::Scalar;
use ff::Field;
use rand::SeedableRng;
use std::iter;
use zkchannels_crypto::challenge::ChallengeBuilder;
use zkchannels_crypto::message::Message;
use zkchannels_crypto::ps_keys::KeyPair;
use zkchannels_crypto::ps_signatures::Signer;
use zkchannels_crypto::signature_proof::SignatureProofBuilder;
use zkchannels_crypto::Rng;

// Seeded rng for replicable tests.
fn rng() -> impl Rng {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[test]
fn signature_proof_verifies() {
    let mut rng = rng();
    let length = 3;

    // Generate message and form signature.
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let kp = KeyPair::new(length, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

    // Construct proof.
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

    // Proof must verify with the same challenge and keypair.
    assert!(proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
}

#[test]
fn signature_linear_relation() {
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
    let msg = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);

    // Sign the messages
    let kp = KeyPair::new(length, &mut rng);
    let sig1 = kp.try_sign(&mut rng, &msg).unwrap();
    let sig2 = kp.try_sign(&mut rng, &msg2).unwrap();

    // Form proofs - commitment phase. The commitment scalars for the matching elements must match.
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

    // Form challenge from both proof transcripts.
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder1)
        .with_signature_proof(&sig_proof_builder2)
        .finish();

    // Complete proofs - response phase.
    let proof1 = sig_proof_builder1
        .generate_proof_response(challenge)
        .unwrap();
    let proof2 = sig_proof_builder2
        .generate_proof_response(challenge)
        .unwrap();

    // Proofs must verify.
    assert!(proof1
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert!(proof2
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());

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
    let length = 3;
    // Form message and signature.
    let msg = Message::new(
        iter::repeat_with(|| Scalar::random(&mut rng))
            .take(length)
            .collect(),
    );
    let kp = KeyPair::new(length, &mut rng);
    let sig = kp.try_sign(&mut rng, &msg).unwrap();

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        sig,
        &[None; 3],
        kp.public_key(),
    )
    .unwrap();
    // Save commitment scalars for publicly revealed values (in this case, all of them).
    let commitment_scalars = sig_proof_builder.conjunction_commitment_scalars().to_vec();
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder)
        .finish();
    let proof = sig_proof_builder
        .generate_proof_response(challenge)
        .unwrap();

    // Proof must verify.
    assert!(proof
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());

    // Verify response scalars are correctly formed w.r.t public message and revealed commitment scalars.
    let response_scalars = proof.conjunction_response_scalars();
    assert_eq!(
        msg[0] * challenge.0 + commitment_scalars[0],
        response_scalars[0]
    );
    assert_eq!(
        msg[1] * challenge.0 + commitment_scalars[1],
        response_scalars[1]
    );
    assert_eq!(
        msg[2] * challenge.0 + commitment_scalars[2],
        response_scalars[2]
    );
}

#[test]
fn signature_linear_relation_public_addition() {
    let mut rng = rng();
    // Create messages of the form [a], [a + public_value].
    let public_value = Scalar::random(&mut rng);
    let msg_vec1 = vec![Scalar::random(&mut rng)];
    let msg_vec2 = vec![msg_vec1[0] + public_value];
    let msg = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);

    // Form signatures on messages.
    let kp = KeyPair::new(1, &mut rng);
    let sig1 = kp.try_sign(&mut rng, &msg).unwrap();
    let sig2 = kp.try_sign(&mut rng, &msg2).unwrap();

    // Proof commitment phase: use matching commitment scalars for message values with linear relationship.
    let sig_proof_builder1 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig1,
        &[None; 1],
        kp.public_key(),
    )
    .unwrap();
    let sig_proof_builder2 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2,
        sig2,
        &[Some(sig_proof_builder1.conjunction_commitment_scalars()[0])],
        kp.public_key(),
    )
    .unwrap();

    // Construct challenge using both proofs.
    let challenge = ChallengeBuilder::new()
        .with_signature_proof(&sig_proof_builder1)
        .with_signature_proof(&sig_proof_builder2)
        .finish();

    // Form proofs - response phase.
    let proof1 = sig_proof_builder1
        .generate_proof_response(challenge)
        .unwrap();
    let proof2 = sig_proof_builder2
        .generate_proof_response(challenge)
        .unwrap();

    // Both signature proofs must verify.
    assert!(proof1
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());
    assert!(proof2
        .verify_knowledge_of_signature(kp.public_key(), challenge)
        .unwrap());

    // The expected linear relationship must hold for the response scalars.
    assert_eq!(
        proof1.conjunction_response_scalars()[0] + challenge.0 * public_value,
        proof2.conjunction_response_scalars()[0]
    );
}
