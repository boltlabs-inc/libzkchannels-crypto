mod test_utils;

use arrayvec::ArrayVec;
use bls12_381::*;
use ff::Field;
use group::{Group, GroupEncoding};
use rand::Rng;
use std::iter;
use zkchannels_crypto::{
    pedersen::Commitment,
    pedersen::PedersenParameters,
    proofs::{ChallengeBuilder, CommitmentProof, CommitmentProofBuilder},
    BlindingFactor, Message, SerializeElement,
};

#[test]
fn commitment_proof_verifies() {
    run_commitment_proof_verifies::<1>();
    run_commitment_proof_verifies::<2>();
    run_commitment_proof_verifies::<3>();
    run_commitment_proof_verifies::<5>();
    run_commitment_proof_verifies::<8>();
    run_commitment_proof_verifies::<13>();
}

fn run_commitment_proof_verifies<const N: usize>() {
    let mut rng = test_utils::seeded_rng();

    // Generate message.
    let msg = Message::<N>::random(&mut rng);

    // Form commmitment.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Build proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg, &[None; N], &params);
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(challenge);

    // Proof must verify with the original commit.
    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));
}

#[test]
fn commitment_proof_fails_on_wrong_commit() {
    run_commitment_proof_fails_on_wrong_commit::<1>();
    run_commitment_proof_fails_on_wrong_commit::<2>();
    run_commitment_proof_fails_on_wrong_commit::<3>();
    run_commitment_proof_fails_on_wrong_commit::<5>();
    run_commitment_proof_fails_on_wrong_commit::<8>();
    run_commitment_proof_fails_on_wrong_commit::<13>();
}

fn run_commitment_proof_fails_on_wrong_commit<const N: usize>() {
    let mut rng = test_utils::seeded_rng();

    // Generate message.
    let msg = Message::<N>::random(&mut rng);

    // Form the "correct" commmitment.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Build proof.
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        &[None; N],
        &params,
    );
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof_builder_for_bad_params = proof_builder.clone();
    let proof_builder_for_bad_com = proof_builder.clone();
    let proof = proof_builder.generate_proof_response(challenge);

    // Proof must not verify on a commitment with the wrong blinding factor.
    let bad_bf = BlindingFactor::new(&mut rng);
    let bad_bf_com = params.commit(&msg, bad_bf);
    assert_ne!(
        proof.commitment(),
        bad_bf_com,
        "Unfortunate RNG seed: Accidentally generated matching messages."
    );
    let bad_proof = modify_proof::<N>(&proof, &bad_bf_com);
    let verif_challenge = ChallengeBuilder::new().with(&bad_proof).finish();
    assert!(
        !bad_proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge),
        "Proof verified on commitment with wrong blinding factor."
    );

    // Proof must not verify on a commitment with the wrong parameters.
    let bad_params = PedersenParameters::<G1Projective, N>::new(&mut rng);
    let bad_params_com =
        bad_params.commit(&msg, proof_builder_for_bad_params.message_blinding_factor());
    assert_ne!(
        proof.commitment(),
        bad_params_com,
        "Unfortunate RNG seed: Accidentally generated matching messages."
    );
    let bad_proof = modify_proof::<N>(&proof, &bad_params_com);
    let verif_challenge = ChallengeBuilder::new().with(&bad_proof).finish();
    assert!(
        !proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge),
        "Proof verified on commitment with wrong parameters."
    );

    // Proof must to verify on a commitment with the wrong message.
    let bad_msg = Message::<N>::random(&mut rng);
    assert_ne!(&*msg, &*bad_msg, "Accidentally generated matching messages");
    let bad_msg_com = params.commit(
        &bad_msg,
        proof_builder_for_bad_com.message_blinding_factor(),
    );
    let bad_proof = modify_proof::<N>(&proof, &bad_msg_com);
    let verif_challenge = ChallengeBuilder::new().with(&bad_proof).finish();
    assert!(
        !proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge),
        "Proof verified on commitment with wrong message."
    );
}

fn modify_proof<const N: usize>(
    proof: &CommitmentProof<G1Projective, N>,
    bad_bf_com: &Commitment<G1Projective>,
) -> CommitmentProof<G1Projective, N> {
    let mut ser_proof = bincode::serialize(&proof).unwrap();
    let ser_com = bincode::serialize(&proof.commitment()).unwrap();
    let pos = (0..ser_proof.len() - ser_com.len() + 1)
        .find(|&i| ser_proof[i..i + ser_com.len()] == ser_com[..])
        .unwrap();
    let ser_bad_com = bincode::serialize(&bad_bf_com).unwrap();
    ser_proof[pos..(pos + ser_bad_com.len())].clone_from_slice(&ser_bad_com[..]);
    bincode::deserialize::<CommitmentProof<G1Projective, N>>(&ser_proof).unwrap()
}

#[test]
fn commitment_proof_fails_on_wrong_challenge() {
    run_commitment_proof_fails_on_wrong_challenge::<1>();
    run_commitment_proof_fails_on_wrong_challenge::<2>();
    run_commitment_proof_fails_on_wrong_challenge::<3>();
    run_commitment_proof_fails_on_wrong_challenge::<5>();
    run_commitment_proof_fails_on_wrong_challenge::<8>();
    run_commitment_proof_fails_on_wrong_challenge::<13>();
}

fn run_commitment_proof_fails_on_wrong_challenge<const N: usize>() {
    let mut rng = test_utils::seeded_rng();

    // Generate message.
    let msg = Message::<N>::random(&mut rng);

    // Form commmitment.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Build proof using normally-generated challenge.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg, &[None; N], &params);
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
    assert!(!proof.verify_knowledge_of_opening_of_commitment(&params, bad_challenge));
}

#[test]
fn commitment_proof_with_equality_relation() {
    run_commitment_proof_with_equality_relation::<1>();
    run_commitment_proof_with_equality_relation::<2>();
    run_commitment_proof_with_equality_relation::<3>();
    run_commitment_proof_with_equality_relation::<5>();
    run_commitment_proof_with_equality_relation::<8>();
    run_commitment_proof_with_equality_relation::<13>();
}

fn run_commitment_proof_with_equality_relation<const N: usize>() {
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
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Construct proofs - commitment phase.
    let proof_builder1 =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg1, &[None; N], &params);
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[second_pos] =
        Some(proof_builder1.conjunction_commitment_scalars()[first_pos]);
    // Set commitment scalars for the matching elements to be equal:
    // Pass in the commitment scalar of the first position onto the third position.
    let proof_builder2 = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2,
        &conjunction_commitment_scalars,
        &params,
    );

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with(&proof_builder1)
        .with(&proof_builder2)
        .finish();

    // Complete proofs - response phase.
    let proof1 = proof_builder1.generate_proof_response(challenge);
    let proof2 = proof_builder2.generate_proof_response(challenge);

    // Verify both proofs.
    let verif_challenge = ChallengeBuilder::new().with(&proof1).with(&proof2).finish();
    assert!(proof1.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));
    assert!(proof2.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));

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
}

#[test]
fn commitment_proof_with_public_value() {
    run_commitment_proof_with_public_value::<1>();
    run_commitment_proof_with_public_value::<2>();
    run_commitment_proof_with_public_value::<3>();
    run_commitment_proof_with_public_value::<5>();
    run_commitment_proof_with_public_value::<8>();
    run_commitment_proof_with_public_value::<13>();
}

fn run_commitment_proof_with_public_value<const N: usize>() {
    let mut rng = test_utils::seeded_rng();
    let mut real_rng = test_utils::real_rng();

    // Construct message and commitment.
    let msg = Message::<N>::random(&mut rng);
    let public_pos = real_rng.gen_range(0..N);
    let public_value = msg[public_pos];
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Construct proof.
    let proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg, &[None; N], &params);
    // Save commitment scalars for public elements (in this case, all of them).
    let commitment_scalars = proof_builder.conjunction_commitment_scalars().to_vec();
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof = proof_builder.generate_proof_response(challenge);

    // Verify underlying proof.
    let verif_challenge = ChallengeBuilder::new().with(&proof).finish();
    assert!(proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));

    // Verify response scalars are correctly formed against the public msg. The commitment_scalar for the public value is revealed alongside the proof
    let response_scalars = proof.conjunction_response_scalars();
    assert_eq!(
        public_value * verif_challenge.to_scalar() + commitment_scalars[public_pos],
        response_scalars[public_pos]
    );
}

#[test]
fn commitment_proof_with_linear_relation_public_addition() {
    run_commitment_proof_with_linear_relation_public_addition::<1>();
    run_commitment_proof_with_linear_relation_public_addition::<2>();
    run_commitment_proof_with_linear_relation_public_addition::<3>();
    run_commitment_proof_with_linear_relation_public_addition::<5>();
    run_commitment_proof_with_linear_relation_public_addition::<8>();
    run_commitment_proof_with_linear_relation_public_addition::<13>();
}

fn run_commitment_proof_with_linear_relation_public_addition<const N: usize>() {
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
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);

    // Construct proof - commitment phase.
    let proof_builder1 =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, msg1, &[None; N], &params);
    // Commitment scalars for elements with linear relationships must match.
    let mut conjunction_commitment_scalars = [None; N];
    conjunction_commitment_scalars[second_pos] =
        Some(proof_builder1.conjunction_commitment_scalars()[first_pos]);
    let proof_builder2 = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg2,
        &conjunction_commitment_scalars,
        &params,
    );

    // Create a challenge from both transcripts.
    let challenge = ChallengeBuilder::new()
        .with(&proof_builder1)
        .with(&proof_builder2)
        .finish();
    let proof1 = proof_builder1.generate_proof_response(challenge);
    let proof2 = proof_builder2.generate_proof_response(challenge);

    // Verify both proofs.
    let verif_challenge = ChallengeBuilder::new().with(&proof1).with(&proof2).finish();
    assert!(proof1.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));
    assert!(proof2.verify_knowledge_of_opening_of_commitment(&params, verif_challenge));

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
}

fn commitment_proof_fails_on_random_commit<
    G: Group<Scalar = Scalar> + GroupEncoding + SerializeElement,
>() {
    let mut rng = test_utils::seeded_rng();

    // Generate message.
    let msg = Message::<3>::random(&mut rng);

    // Form the "correct" commmitment.
    let params = PedersenParameters::<G, 3>::new(&mut rng);

    // Build proof.
    let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
        &[None; 3],
        &params,
    );
    let challenge = ChallengeBuilder::new().with(&proof_builder).finish();
    let proof_builder_for_bad_com = proof_builder.clone();
    let proof = proof_builder.generate_proof_response(challenge);

    // Generate a bad commitment by deserializing it from a random element in G.
    let mut bytes = Vec::<u8>::new();
    SerializeElement::serialize(
        &G::random(&mut rng),
        &mut bincode::Serializer::new(&mut bytes, bincode::options()),
    )
    .unwrap();
    let bad_com: Commitment<G> = bincode::deserialize(&bytes).unwrap();
    // Make sure new commitment isn't accidentally the correct one.
    assert_ne!(
        params.commit(&msg, proof_builder_for_bad_com.message_blinding_factor()),
        bad_com,
        "Unfortunate RNG seed: Accidentally generated the correct commitment."
    );

    // Proof must not verify
    let verif_challenge = ChallengeBuilder::new()
        .with(&proof.scalar_commitment())
        .finish();
    assert!(
        !proof.verify_knowledge_of_opening_of_commitment(&params, verif_challenge),
        "Proof verified on totally random commitment."
    );
}

#[test]
fn commitment_proof_fails_on_random_commit_g1() {
    commitment_proof_fails_on_random_commit::<G1Projective>()
}

#[test]
fn commitment_proof_fails_on_random_commit_g2() {
    commitment_proof_fails_on_random_commit::<G2Projective>()
}
