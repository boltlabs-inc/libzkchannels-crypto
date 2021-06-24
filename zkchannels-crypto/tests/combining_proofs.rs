use arrayvec::ArrayVec;
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use futures::try_join;
use rand::{Rng, SeedableRng};
use std::iter;
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

/// Prove knowledge of a signature and knowledge of opening of a commitment that are on the same
/// message. This test constructs the signataure proof first.
#[tokio::test(flavor = "multi_thread")]
async fn signature_commitment_proof_linear_relation() {
    try_join!(
        tokio::spawn(run_signature_commitment_proof_linear_relation::<1>()),
        tokio::spawn(run_signature_commitment_proof_linear_relation::<2>()),
        tokio::spawn(run_signature_commitment_proof_linear_relation::<3>()),
        tokio::spawn(run_signature_commitment_proof_linear_relation::<5>()),
        tokio::spawn(run_signature_commitment_proof_linear_relation::<8>()),
        tokio::spawn(run_signature_commitment_proof_linear_relation::<13>())
    )
    .unwrap();
}

async fn run_signature_commitment_proof_linear_relation<const N: usize>() {
    let mut rng = rng();
    // Generate message.
    let msg = Message::<N>::random(&mut rng);

    // Form signature on message.
    let kp = KeyPair::<N>::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Form commitment on message.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

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
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &ccs, &params);

    // Form challenge from both proofs.
    let challenge = ChallengeBuilder::new()
        .with(&sig_proof_builder)
        .with(&com_proof_builder)
        .finish();

    // Complete proofs - response phase.
    let sig_proof = sig_proof_builder.generate_proof_response(challenge);
    let com_proof = com_proof_builder.generate_proof_response(&msg, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&sig_proof)
        .with(&com_proof)
        .finish();
    // Verify commitment proof is valid.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));
    // Verify signature proof is valid.
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    // Verify they are on the same message - response scalars must match.
    assert_eq!(
        com_proof.conjunction_response_scalars(),
        sig_proof.conjunction_response_scalars()
    );
}

#[tokio::test(flavor = "multi_thread")]
/// Prove knowledge of a signature and knowledge of opening of a commitment that are on the same
/// message. This test constructs the commitment proof first.
async fn commitment_signature_proof_linear_relation() {
    try_join!(
        tokio::spawn(run_commitment_signature_proof_linear_relation::<1>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation::<2>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation::<3>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation::<5>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation::<8>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation::<13>())
    )
    .unwrap();
}

async fn run_commitment_signature_proof_linear_relation<const N: usize>() {
    let mut rng = rng();
    // Generate message.
    let msg = Message::<N>::random(&mut rng);
    // Form signature on message
    let kp = KeyPair::<N>::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Form commitment to message.
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg, bf);

    // Construct proof - commitment phase.
    // Use matching commitment scalars for each message item.
    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; N], &params);
    let ccs = com_proof_builder
        .conjunction_commitment_scalars()
        .iter()
        .map(|&ccs| Some(ccs))
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    let sig_proof_builder = SignatureProofBuilder::generate_proof_commitments(
        &mut rng,
        msg.clone(),
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
    let com_proof = com_proof_builder.generate_proof_response(&msg, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&com_proof)
        .with(&sig_proof)
        .finish();
    // Commitment proof must be valid.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));
    // Signature proof must be valid.
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    // Proofs must be on the same message - e.g. have matching response scalars.
    assert_eq!(
        com_proof.conjunction_response_scalars(),
        sig_proof.conjunction_response_scalars()
    );
}

#[tokio::test(flavor = "multi_thread")]
/// Prove knowledge of a signature and of opening of a commitment that have a linear relationship
/// with each other and a public value:
/// Sig( a ); Com( a + public_value )
async fn commitment_signature_proof_linear_relation_public_addition() {
    try_join!(
        tokio::spawn(run_commitment_signature_proof_linear_relation_public_addition::<1>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation_public_addition::<2>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation_public_addition::<3>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation_public_addition::<5>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation_public_addition::<8>()),
        tokio::spawn(run_commitment_signature_proof_linear_relation_public_addition::<13>())
    )
    .unwrap();
}

async fn run_commitment_signature_proof_linear_relation_public_addition<const N: usize>() {
    let mut rng = rng();
    // Form message [a]; [a + public_value]
    let public_value = Scalar::random(&mut rng);
    let msg = Message::<N>::random(&mut rng);
    let first_pos = rng.gen_range(0..N);
    let second_pos = rng.gen_range(0..N);
    let mut msg2_vec = iter::repeat_with(|| Scalar::random(&mut rng))
        .take(N)
        .collect::<ArrayVec<_, N>>()
        .into_inner()
        .expect("length mismatch impossible");
    msg2_vec[second_pos] = msg[first_pos] + public_value;
    let msg2 = Message::new(msg2_vec);

    // Sign [a].
    let kp = KeyPair::new(&mut rng);
    let sig = kp.sign(&mut rng, &msg);

    // Commit to [a + public_value].
    let params = PedersenParameters::<G1Projective, N>::new(&mut rng);
    let bf = BlindingFactor::new(&mut rng);
    let com = params.commit(&msg2, bf);

    // Proof commitment phase: use the same commitment scalar for both messages.
    let com_proof_builder =
        CommitmentProofBuilder::generate_proof_commitments(&mut rng, &[None; N], &params);
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
    let com_proof = com_proof_builder.generate_proof_response(&msg2, bf, challenge);

    let verif_challenge = ChallengeBuilder::new()
        .with(&sig_proof)
        .with(&com_proof)
        .finish();
    // Both proofs must verify.
    assert!(com_proof.verify_knowledge_of_opening_of_commitment(&params, com, verif_challenge));
    assert!(sig_proof.verify_knowledge_of_signature(kp.public_key(), verif_challenge));
    // The response scalars must have the expected relationship.
    assert_eq!(
        sig_proof.conjunction_response_scalars()[first_pos]
            + verif_challenge.to_scalar() * public_value,
        com_proof.conjunction_response_scalars()[second_pos],
    );
}
