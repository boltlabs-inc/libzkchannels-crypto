use arrayvec::ArrayVec;
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::Rng;
use std::iter;
use zkchannels_crypto::pedersen::ToPedersenParameters;
use zkchannels_crypto::pointcheval_sanders::KeyPair;
use zkchannels_crypto::proofs::{
    ChallengeBuilder, CommitmentProofBuilder, SignatureRequestProofBuilder,
};
use zkchannels_crypto::Message;

mod test_utils;

#[test]
fn signature_request_proof_verifies() {
    run_signature_request_proof_verifies::<1>();
    run_signature_request_proof_verifies::<2>();
    run_signature_request_proof_verifies::<3>();
    run_signature_request_proof_verifies::<5>();
    run_signature_request_proof_verifies::<8>();
    run_signature_request_proof_verifies::<13>();
}

fn run_signature_request_proof_verifies<const N: usize>() {
    let mut rng = test_utils::seeded_rng();

    // Generate message.
    let msg = Message::<N>::random(&mut rng);

    // Form commmitment.
    let keypair = KeyPair::new(&mut rng);

    // Build proof.
    let proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        &[None; N],
        keypair.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let bf = proof_builder.message_blinding_factor();
    let proof = proof_builder.generate_proof_response(challenge);

    // Proof must verify with the original commit.
    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    let verified_blinded_message =
        proof.verify_knowledge_of_blinded_message(keypair.public_key(), verif_challenge);
    assert!(verified_blinded_message.is_some());
    let blinded_signature = verified_blinded_message
        .unwrap()
        .blind_sign(&keypair, &mut rng);
    let signature = blinded_signature.unblind(bf);
    assert!(signature.verify(keypair.public_key(), &msg));
}

#[test]
fn signature_request_proof_fails_on_wrong_challenge() {
    run_signature_request_proof_fails_on_wrong_challenge::<1>();
    run_signature_request_proof_fails_on_wrong_challenge::<2>();
    run_signature_request_proof_fails_on_wrong_challenge::<3>();
    run_signature_request_proof_fails_on_wrong_challenge::<5>();
    run_signature_request_proof_fails_on_wrong_challenge::<8>();
    run_signature_request_proof_fails_on_wrong_challenge::<13>();
}

fn run_signature_request_proof_fails_on_wrong_challenge<const N: usize>() {
    let mut rng = test_utils::seeded_rng();

    // Generate message.
    let msg = Message::<N>::random(&mut rng);

    // Form commmitment.
    let keypair = KeyPair::new(&mut rng);

    // Build proof using normally-generated challenge.
    let proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
        &mut rng,
        msg,
        &[None; N],
        keypair.public_key(),
    );
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(challenge);

    // Proof must *not* verify with the wrong challenge.
    let random_bytes = rng.gen::<[u8; 32]>();
    let bad_challenge = ChallengeBuilder::new().with_bytes(&random_bytes).finish();
    assert_ne!(
        bad_challenge.to_scalar(),
        challenge.to_scalar(),
        "Accidentally generated matching challenge."
    );
    assert!(proof
        .verify_knowledge_of_blinded_message(keypair.public_key(), bad_challenge)
        .is_none());
}

#[test]
fn signature_request_proof_with_equality_relation() {
    run_signature_request_proof_with_equality_relation::<1>();
    run_signature_request_proof_with_equality_relation::<2>();
    run_signature_request_proof_with_equality_relation::<3>();
    run_signature_request_proof_with_equality_relation::<5>();
    run_signature_request_proof_with_equality_relation::<8>();
    run_signature_request_proof_with_equality_relation::<13>();
}

fn run_signature_request_proof_with_equality_relation<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Construct messages of the form [a, ., .]; [., ., a]
    // e.g. the last element of the second equals the first element of the first.
    let msg1 = Message::<N>::random(&mut rng);
    let first_pos = real_rng.gen_range(0..N);
    let second_pos = real_rng.gen_range(0..N);
    let mut msg2_vec = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    msg2_vec[second_pos] = msg1[first_pos];
    let msg2 = Message::new(msg2_vec);

    // Construct commitments.
    let params = KeyPair::new(&mut rng);

    // Construct proofs - commitment phase.
    let proof_builder1 = CommitmentProofBuilder::<G1Projective, N>::generate_proof_commitments(
        &mut rng,
        msg1,
        &[None; N],
        &params.public_key().to_pedersen_parameters(),
    );
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[second_pos] =
        Some(proof_builder1.conjunction_commitment_scalars()[first_pos]);
    // Set commitment scalars for the matching elements to be equal:
    // Pass in the commitment scalar of the first position onto the third position.
    let proof_builder2 = SignatureRequestProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2.clone(),
        &conjunction_commitment_scalars,
        params.public_key(),
    );

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with(&proof_builder1)
        .with(&proof_builder2)
        .finish();

    // Complete proofs - response phase.
    let proof1 = proof_builder1.generate_proof_response(challenge);
    let bf2 = proof_builder2.message_blinding_factor();
    let proof2 = proof_builder2.generate_proof_response(challenge);

    // Verify both proofs.
    let verif_challenge = ChallengeBuilder::new().with(&proof1).with(&proof2).finish();
    assert!(proof1.verify_knowledge_of_opening_of_commitment(
        &params.public_key().to_pedersen_parameters(),
        verif_challenge
    ));
    let verif_blind_msg2 =
        proof2.verify_knowledge_of_blinded_message(params.public_key(), verif_challenge);
    assert!(verif_blind_msg2.is_some());

    // Verify linear equation.
    assert_eq!(
        proof1.conjunction_response_scalars()[first_pos],
        proof2.conjunction_response_scalars()[second_pos]
    );
    // Verify the above was not an accident. (such as all elements are the same, or there are other equalities)
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

    let blinded_signature2 = verif_blind_msg2.unwrap().blind_sign(&params, &mut rng);
    let signature = blinded_signature2.unblind(bf2);
    assert!(signature.verify(params.public_key(), &msg2));
}

#[test]
fn signature_request_proof_with_public_value() {
    run_signature_request_proof_with_public_value::<1>();
    run_signature_request_proof_with_public_value::<2>();
    run_signature_request_proof_with_public_value::<3>();
    run_signature_request_proof_with_public_value::<5>();
    run_signature_request_proof_with_public_value::<8>();
    run_signature_request_proof_with_public_value::<13>();
}

fn run_signature_request_proof_with_public_value<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Construct message and commitment.
    let msg = Message::<N>::random(&mut rng);
    let public_pos = real_rng.gen_range(0..N);
    let public_value = msg[public_pos];
    let params = KeyPair::new(&mut rng);

    // Construct proof.
    let proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        &[None; N],
        params.public_key(),
    );
    let bf = proof_builder.message_blinding_factor();
    // Save commitment scalars for public elements (in this case, all of them).
    let commitment_scalars = proof_builder.conjunction_commitment_scalars().to_vec();
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(challenge);

    // Verify underlying proof.
    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    let verif_blind_msg =
        proof.verify_knowledge_of_blinded_message(params.public_key(), verif_challenge);
    assert!(verif_blind_msg.is_some());

    // Verify response scalars are correctly formed against the public msg. The commitment_scalar for the public value is revealed alongside the proof
    let response_scalars = proof.conjunction_response_scalars();
    assert_eq!(
        public_value * verif_challenge.to_scalar() + commitment_scalars[public_pos],
        response_scalars[public_pos]
    );

    let blinded_signature = verif_blind_msg.unwrap().blind_sign(&params, &mut rng);
    let signature = blinded_signature.unblind(bf);
    assert!(signature.verify(params.public_key(), &msg));
}

#[test]
fn signature_request_proof_with_linear_relation_public_addition() {
    run_signature_request_proof_with_linear_relation_public_addition::<1>();
    run_signature_request_proof_with_linear_relation_public_addition::<2>();
    run_signature_request_proof_with_linear_relation_public_addition::<3>();
    run_signature_request_proof_with_linear_relation_public_addition::<5>();
    run_signature_request_proof_with_linear_relation_public_addition::<8>();
    run_signature_request_proof_with_linear_relation_public_addition::<13>();
}

fn run_signature_request_proof_with_linear_relation_public_addition<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Construct messages of the form [a]; [a + public_value]
    // e.g. the last element of the second equals the first element of the first.
    let public_value = Scalar::random(&mut rng);

    let msg1 = Message::<N>::random(&mut rng);
    let first_pos = real_rng.gen_range(0..N);
    let second_pos = real_rng.gen_range(0..N);
    let mut msg2_vec = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    msg2_vec[second_pos] = msg1[first_pos] + public_value;
    let msg2 = Message::new(msg2_vec);

    // Construct commitments.
    let params = KeyPair::new(&mut rng);

    // Construct proof - commitment phase.
    let proof_builder1 = CommitmentProofBuilder::<G1Projective, N>::generate_proof_commitments(
        &mut rng,
        msg1,
        &[None; N],
        &params.public_key().to_pedersen_parameters(),
    );
    // Commitment scalars for elements with linear relationships must match.
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[second_pos] =
        Some(proof_builder1.conjunction_commitment_scalars()[first_pos]);
    let proof_builder2 = SignatureRequestProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2.clone(),
        &conjunction_commitment_scalars,
        params.public_key(),
    );

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with(&proof_builder1)
        .with(&proof_builder2)
        .finish();
    let proof1 = proof_builder1.generate_proof_response(challenge);
    let bf2 = proof_builder2.message_blinding_factor();
    let proof2 = proof_builder2.generate_proof_response(challenge);

    // Verify both proofs.
    let verif_challenge = ChallengeBuilder::new().with(&proof1).with(&proof2).finish();
    assert!(proof1.verify_knowledge_of_opening_of_commitment(
        &params.public_key().to_pedersen_parameters(),
        verif_challenge
    ));
    let verif_blind_msg2 =
        proof2.verify_knowledge_of_blinded_message(params.public_key(), verif_challenge);
    assert!(verif_blind_msg2.is_some());

    // Verify linear equation.
    assert_eq!(
        proof1.conjunction_response_scalars()[first_pos]
            + verif_challenge.to_scalar() * public_value,
        proof2.conjunction_response_scalars()[second_pos]
    );
    // Verify the above was not an accident. (such as all elements are the same, or there are other equalities)
    for i in 0..N {
        for j in 0..N {
            if i != first_pos && j != second_pos {
                assert_ne!(
                    proof1.conjunction_response_scalars()[i]
                        + verif_challenge.to_scalar() * public_value,
                    proof2.conjunction_response_scalars()[j]
                );
            }
        }
    }

    let blinded_signature2 = verif_blind_msg2.unwrap().blind_sign(&params, &mut rng);
    let signature = blinded_signature2.unblind(bf2);
    assert!(signature.verify(params.public_key(), &msg2));
}
