mod test_utils;

use arrayvec::ArrayVec;
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::Rng;
use std::iter;
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    pointcheval_sanders::KeyPair,
    proofs::{ChallengeBuilder, CommitmentProofBuilder, SignatureProofBuilder},
    Message,
};

#[test]
/// Prove knowledge of a signature and knowledge of opening of a commitment that are on the same
/// message. This test constructs the signataure proof first.
fn signature_commitment_proof_linear_relation() {
    run_signature_commitment_proof_linear_relation::<1>();
    run_signature_commitment_proof_linear_relation::<2>();
    run_signature_commitment_proof_linear_relation::<3>();
    run_signature_commitment_proof_linear_relation::<5>();
    run_signature_commitment_proof_linear_relation::<8>();
    run_signature_commitment_proof_linear_relation::<13>();
}

fn run_signature_commitment_proof_linear_relation<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    // Generate message.
    let msg = Message::<N>::random(&mut rng);

    // Form signature on message.
    let kp = KeyPair::<N>::new(&mut rng);
    let sig = msg.sign(&mut rng, &kp);

    // Form commitment on message.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Construct proof - commitment phase.
    // Use matching commitment scalars for each message item.
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        sig,
        &[None; N],
        kp.public_key(),
    );
    let ccs = sig_proof_builder
        .conjunction_commitment_scalars()
        .iter()
        .map(|&ccs| Some(ccs))
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg, &ccs, &params);

    // Form challenge from both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&sig_proof_builder)
        .with(&com_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let sig_proof = sig_proof_builder.generate_proof_response(challenge);
    let com_proof = com_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&sig_proof)
        .with(&com_proof)
        .finish();
    // Verify commitment proof is valid.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));
    // Verify signature proof is valid.
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
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
    run_commitment_signature_proof_linear_relation::<1>();
    run_commitment_signature_proof_linear_relation::<2>();
    run_commitment_signature_proof_linear_relation::<3>();
    run_commitment_signature_proof_linear_relation::<5>();
    run_commitment_signature_proof_linear_relation::<8>();
    run_commitment_signature_proof_linear_relation::<13>();
}

fn run_commitment_signature_proof_linear_relation<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    // Generate message.
    let msg = Message::<N>::random(&mut rng);
    // Form signature on message
    let kp = KeyPair::<N>::new(&mut rng);
    let sig = msg.sign(&mut rng, &kp);

    // Form commitment to message.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Construct proof - commitment phase.
    // Use matching commitment scalars for each message item.
    let com_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        &[None; N],
        &params,
    );
    let ccs = com_proof_builder
        .conjunction_commitment_scalars()
        .iter()
        .map(|&ccs| Some(ccs))
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &ccs,
        kp.public_key(),
    );

    // Form challenge from both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&com_proof_builder)
        .with(&sig_proof_builder)
        .finish();

    // Complete proofs.
    let sig_proof = sig_proof_builder.generate_proof_response(challenge);
    let com_proof = com_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&com_proof)
        .with(&sig_proof)
        .finish();
    // Commitment proof must be valid.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));
    // Signature proof must be valid.
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
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
    run_commitment_signature_proof_linear_relation_public_addition::<1>();
    run_commitment_signature_proof_linear_relation_public_addition::<2>();
    run_commitment_signature_proof_linear_relation_public_addition::<3>();
    run_commitment_signature_proof_linear_relation_public_addition::<5>();
    run_commitment_signature_proof_linear_relation_public_addition::<8>();
    run_commitment_signature_proof_linear_relation_public_addition::<13>();
}

fn run_commitment_signature_proof_linear_relation_public_addition<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();
    // Form message [a]; [a + public_value]
    let public_value = Scalar::random(&mut rng);
    let msg = Message::<N>::random(&mut rng);
    let first_pos = real_rng.gen_range(0..N);
    let second_pos = real_rng.gen_range(0..N);
    let mut msg2_vec = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    msg2_vec[second_pos] = msg[first_pos] + public_value;
    let msg2 = Message::new(msg2_vec);

    // Sign [a].
    let kp = KeyPair::new(&mut rng);
    let sig = msg.sign(&mut rng, &kp);

    // Commit to [a + public_value].
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Proof commitment phase: use the same commitment scalar for both messages.
    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg2, &[None; N], &params);
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[first_pos] =
        Some(com_proof_builder.conjunction_commitment_scalars()[second_pos]);
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        sig,
        &conjunction_commitment_scalars,
        kp.public_key(),
    );

    // Form challenge, integrating both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&sig_proof_builder)
        .with(&com_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let sig_proof = sig_proof_builder.generate_proof_response(challenge);
    let com_proof = com_proof_builder.generate_proof_response(challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&sig_proof)
        .with(&com_proof)
        .finish();
    // Both proofs must verify.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    // The response scalars must have the expected relationship.
    assert_eq!(
        sig_proof.conjunction_response_scalars()[first_pos]
            + verif_challenge.to_scalar() * public_value,
        com_proof.conjunction_response_scalars()[second_pos],
    );
}
