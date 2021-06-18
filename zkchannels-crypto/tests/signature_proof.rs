use arrayvec::ArrayVec;
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
    run_signature_proof_verifies::<1>();
    run_signature_proof_verifies::<2>();
    run_signature_proof_verifies::<3>();
    run_signature_proof_verifies::<5>();
    run_signature_proof_verifies::<8>();
    run_signature_proof_verifies::<13>();
}

fn run_signature_proof_verifies<const N: usize>() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<N>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; N],
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
    run_signature_proof_fails_with_wrong_message::<1>();
    run_signature_proof_fails_with_wrong_message::<2>();
    run_signature_proof_fails_with_wrong_message::<3>();
    run_signature_proof_fails_with_wrong_message::<5>();
    run_signature_proof_fails_with_wrong_message::<8>();
    run_signature_proof_fails_with_wrong_message::<13>();
}

fn run_signature_proof_fails_with_wrong_message<const N: usize>() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<N>::random(&mut rng);
    let bad_msg = Message::<N>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof with the wrong message.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        bad_msg,
        sig,
        &[None; N],
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
    run_signature_proof_fails_with_wrong_parameters_for_signature::<1>();
    run_signature_proof_fails_with_wrong_parameters_for_signature::<2>();
    run_signature_proof_fails_with_wrong_parameters_for_signature::<3>();
    run_signature_proof_fails_with_wrong_parameters_for_signature::<5>();
    run_signature_proof_fails_with_wrong_parameters_for_signature::<8>();
    run_signature_proof_fails_with_wrong_parameters_for_signature::<13>();
}

fn run_signature_proof_fails_with_wrong_parameters_for_signature<const N: usize>() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<N>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let bad_kp = KeyPair::new(&mut rng);

    // Sign message with the wrong parameters.
    let sig = bad_kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; N],
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
    run_signature_proof_fails_with_wrong_parameters_for_proof::<1>();
    run_signature_proof_fails_with_wrong_parameters_for_proof::<2>();
    run_signature_proof_fails_with_wrong_parameters_for_proof::<3>();
    run_signature_proof_fails_with_wrong_parameters_for_proof::<5>();
    run_signature_proof_fails_with_wrong_parameters_for_proof::<8>();
    run_signature_proof_fails_with_wrong_parameters_for_proof::<13>();
}

fn run_signature_proof_fails_with_wrong_parameters_for_proof<const N: usize>() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<N>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let bad_kp = KeyPair::new(&mut rng);

    // Sign message.
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof with the wrong parameters.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; N],
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
    run_signature_proof_fails_with_wrong_parameters_for_verification::<1>();
    run_signature_proof_fails_with_wrong_parameters_for_verification::<2>();
    run_signature_proof_fails_with_wrong_parameters_for_verification::<3>();
    run_signature_proof_fails_with_wrong_parameters_for_verification::<5>();
    run_signature_proof_fails_with_wrong_parameters_for_verification::<8>();
    run_signature_proof_fails_with_wrong_parameters_for_verification::<13>();
}

fn run_signature_proof_fails_with_wrong_parameters_for_verification<const N: usize>() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<N>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);
    let bad_kp = KeyPair::new(&mut rng);

    // Sign message.
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; N],
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
    run_signature_proof_fails_with_wrong_challenge::<1>();
    run_signature_proof_fails_with_wrong_challenge::<2>();
    run_signature_proof_fails_with_wrong_challenge::<3>();
    run_signature_proof_fails_with_wrong_challenge::<5>();
    run_signature_proof_fails_with_wrong_challenge::<8>();
    run_signature_proof_fails_with_wrong_challenge::<13>();
}

fn run_signature_proof_fails_with_wrong_challenge<const N: usize>() {
    let mut rng = rng();

    // Generate message and form signature.
    let msg = Message::<N>::random(&mut rng);
    let kp = KeyPair::new(&mut rng);

    // Sign message.
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; N],
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
fn signature_proof_equality_relation() {
    run_signature_proof_equality_relation::<1>();
    run_signature_proof_equality_relation::<2>();
    run_signature_proof_equality_relation::<3>();
    run_signature_proof_equality_relation::<5>();
    run_signature_proof_equality_relation::<8>();
    run_signature_proof_equality_relation::<13>();
}

fn run_signature_proof_equality_relation<const N: usize>() {
    let mut rng = rng();
    // Construct messages of the form [a, ., .]; [., ., a]
    // e.g. where the first and last elements of the two messages must match.
    let msg_vec1 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    let first_pos = rng.gen_range(0..N);
    let second_pos = rng.gen_range(0..N);
    let mut msg_vec2 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    msg_vec2[second_pos] = msg_vec1[first_pos];
    let msg = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);

    // Sign the messages
    let kp = KeyPair::new(&mut rng);
    let sig1 = kp.sign(&mut rng, &msg);
    let sig2 = kp.sign(&mut rng, &msg2);

    // Form proofs - commitment phase. The commitment scalars for the matching elements must match.
    let sig_proof_builder1 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig1,
        &[None; N],
        kp.public_key(),
    );
    let mut conjunction_commitment_scalars = iter::repeat_with(|| None)
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    conjunction_commitment_scalars[second_pos] =
        Some(sig_proof_builder1.conjunction_commitment_scalars()[first_pos]);
    let sig_proof_builder2 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2,
        sig2,
        &conjunction_commitment_scalars,
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
        proof1.conjunction_response_scalars()[first_pos],
        proof2.conjunction_response_scalars()[second_pos]
    );

    // Response scalars for other elements should *not* match!
    for i in 0..N {
        for j in 0..N {
            if i != first_pos && j != second_pos {
                assert_ne!(
                    proof1.conjunction_response_scalars()[i],
                    proof2.conjunction_response_scalars()[j]
                );
            }
        }
    }
}

#[test]
fn signature_proof_public_value() {
    run_signature_proof_public_value::<1>();
    run_signature_proof_public_value::<2>();
    run_signature_proof_public_value::<3>();
    run_signature_proof_public_value::<5>();
    run_signature_proof_public_value::<8>();
    run_signature_proof_public_value::<13>();
}

fn run_signature_proof_public_value<const N: usize>() {
    let mut rng = rng();

    // Form message and signature.
    let msg = Message::<N>::random(&mut rng);
    let pos = rng.gen_range(0..N);
    let public_value = msg[pos];
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Construct proof.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &[None; N],
        kp.public_key(),
    );
    // Save commitment scalars for publicly revealed values (in this case, all of them).
    let commitment_scalars = sig_proof_builder.conjunction_commitment_scalars().to_vec();
    let challenge = ChallengeBuilder::new().with(&sig_proof_builder).finish();
    let proof = sig_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    // Proof must verify.
    assert!(proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));

    // Verify response scalar is correctly formed w.r.t public message and revealed commitment scalar.
    let response_scalars = proof.conjunction_response_scalars();
    assert_eq!(
        public_value * verif_challenge.to_scalar() + commitment_scalars[pos],
        response_scalars[pos]
    );
}

#[test]
fn signature_proof_linear_relation_public_addition() {
    run_signature_proof_linear_relation_public_addition::<1>();
    run_signature_proof_linear_relation_public_addition::<2>();
    run_signature_proof_linear_relation_public_addition::<3>();
    run_signature_proof_linear_relation_public_addition::<5>();
    run_signature_proof_linear_relation_public_addition::<8>();
    run_signature_proof_linear_relation_public_addition::<13>();
}

fn run_signature_proof_linear_relation_public_addition<const N: usize>() {
    let mut rng = rng();
    // Create messages of the form [a], [a + public_value].
    let public_value = Scalar::random(&mut rng);
    let msg_vec1 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    let first_pos = rng.gen_range(0..N);
    let second_pos = rng.gen_range(0..N);
    let mut msg_vec2 = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    msg_vec2[second_pos] = msg_vec1[first_pos] + public_value;
    let msg = Message::new(msg_vec1);
    let msg2 = Message::new(msg_vec2);

    // Form signatures on messages.
    let kp = KeyPair::new(&mut rng);
    let sig1 = kp.sign(&mut rng, &msg);
    let sig2 = kp.sign(&mut rng, &msg2);

    // Proof commitment phase: use matching commitment scalars for message values with linear relationship.
    let sig_proof_builder1 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig1,
        &[None; N],
        kp.public_key(),
    );
    let mut conjunction_commitment_scalars = iter::repeat_with(|| None)
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    conjunction_commitment_scalars[second_pos] =
        Some(sig_proof_builder1.conjunction_commitment_scalars()[first_pos]);
    let sig_proof_builder2 = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2,
        sig2,
        &conjunction_commitment_scalars,
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
        proof1.conjunction_response_scalars()[first_pos]
            + verif_challenge.to_scalar() * public_value,
        proof2.conjunction_response_scalars()[second_pos]
    );
}
