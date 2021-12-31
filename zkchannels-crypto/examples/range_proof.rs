use {
    bls12_381::{G2Projective, Scalar},
    thiserror::Error,
};

use rand::thread_rng;
use zkchannels_crypto::{
    pedersen::PedersenParameters,
    proofs::{
        ChallengeBuilder, CommitmentProof, CommitmentProofBuilder, RangeConstraint,
        RangeConstraintBuilder, RangeConstraintParameters, ValueOutsideRange,
    },
    BlindingFactor, Message, Rng,
};

/// Note on encoding: this small example does not clearly specify an input domain for the
/// commitment part of the proof, so we just take the direct encoding of small values.
/// A range proof implicitly limits the domain of its input to [0, 2^63).;w
/// See Message docs for more details.
fn main() {
    // Generate parameters
    let mut rng = thread_rng();
    let pedersen_parameters = PedersenParameters::new(&mut rng);
    let range_constraint_parameters = RangeConstraintParameters::new(&mut rng);

    // Make a proof that your random number is in the range
    let (blinding_factor, random_number_proof) = match RangeProof::new(
        &mut rng,
        &pedersen_parameters,
        &range_constraint_parameters,
        12345,
    ) {
        Ok(proof) => proof,
        Err(e) => {
            unreachable!("Impossible error while generating proof: {}", e);
        }
    };

    // Anyone can verify the proof without knowing your number
    match random_number_proof.verify(&pedersen_parameters, &range_constraint_parameters) {
        Ok(()) => println!("Yay! Proof verified!"),
        Err(e) => eprintln!("Invalid zk proof! {}", e),
    };

    // You can't make a proof on a number that isn't in the range...
    match RangeProof::new(
        &mut rng,
        &pedersen_parameters,
        &range_constraint_parameters,
        -100,
    ) {
        Ok(_proof) => unreachable!("Impossible error generating range proof on an invalid value!"),
        Err(e) => println!("Got expected error: {}", e),
    };

    // Later, you can reveal the number by sharing it and the blinding factor for the commitment
    assert!(random_number_proof.open_commitment(&pedersen_parameters, blinding_factor, 12345));

    // You can't pretend to have committed to a different number
    assert!(!random_number_proof.open_commitment(&pedersen_parameters, blinding_factor, 888));
}

#[derive(Debug, Error)]
pub enum RangeError {
    #[error(transparent)]
    OutOfRange(#[from] ValueOutsideRange),
    #[error("Commitment proof is not consistent")]
    InconsistentCommitment,
    #[error("Range constraint is not satisfied")]
    InconsistentRangeConstraint,
    #[error("Range constraint parameters failed to validate")]
    InvalidParameters(String),
}

// Zero-knowledge proof of knowledge of a number within the range [0, 2^63).
pub struct RangeProof {
    proof: CommitmentProof<G2Projective, 1>,
    range_constraint: RangeConstraint,
}

impl RangeProof {
    /// Try to create a new `RangeProof`.
    /// This constructor validates the input and fails if the provided `number` is out of range.
    ///
    /// Returns a blinding factor for the commitment part of the proof and the proof itself.
    /// **Important**: the blinding factor should only be shared with the verifier when the prover
    /// is ready to open the commitment!
    pub fn new(
        rng: &mut impl Rng,
        pedersen_parameters: &PedersenParameters<G2Projective, 1>,
        range_constraint_parameters: &RangeConstraintParameters,
        number: i64,
    ) -> Result<(BlindingFactor, Self), RangeError> {
        // Generate range constraint on the value
        let range_constraint_builder = RangeConstraintBuilder::generate_constraint_commitments(
            number,
            range_constraint_parameters,
            rng,
        )?;

        // Commit to the number, using the commitment scalar from the range constraint
        let proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            Message::from(Scalar::from(number as u64)),
            &[Some(range_constraint_builder.commitment_scalar())],
            pedersen_parameters,
        );

        // Generate challenge with all public components of the proof
        // - range proof statement (signature proof statements for each digit + the corresponding
        //   blinded signatures) via `range_constraint_builder`
        // - range constraint parameters
        // - commitment proof statement & commitment (via `proof_builder`)
        // - commitment parameters
        let challenge = ChallengeBuilder::new()
            .with(&range_constraint_builder)
            .with(&range_constraint_parameters)
            .with(&proof_builder)
            .with(pedersen_parameters)
            .finish();

        // Form the proof
        Ok((
            proof_builder.message_blinding_factor(),
            Self {
                proof: proof_builder.generate_proof_response(challenge),
                range_constraint: range_constraint_builder.generate_constraint_response(challenge),
            },
        ))
    }

    pub fn verify(
        &self,
        pedersen_parameters: &PedersenParameters<G2Projective, 1>,
        range_constraint_parameters: &RangeConstraintParameters,
    ) -> Result<(), RangeError> {
        // Verify that the range constraint parameters are correctly formed
        // (in practice, this may have been done already e.g. on receipt of the parameters)
        range_constraint_parameters
            .validate()
            .map_err(RangeError::InvalidParameters)?;

        // Reconstruct challenge with all public components of the proof
        // - range proof statement (signature proof statements for each digit + the corresponding
        //   blinded signatures) via `self.range_constraint`
        // - range constraint parameters
        // - commitment proof statement & commitment (via `self.proof`)
        // - commitment parameters
        let challenge = ChallengeBuilder::new()
            .with(&self.range_constraint)
            .with(&range_constraint_parameters)
            .with(&self.proof)
            .with(pedersen_parameters)
            .finish();

        // Verify the commitment to the number is correct
        if !self
            .proof
            .verify_knowledge_of_opening(pedersen_parameters, challenge)
        {
            return Err(RangeError::InconsistentCommitment);
        }

        // Verify that the range constraint is valid AND that it applies to the correct element
        // in the commitment proof (by passing the corresponding response scalar)
        if !self.range_constraint.verify_range_constraint(
            range_constraint_parameters,
            challenge,
            self.proof.conjunction_response_scalars()[0],
        ) {
            return Err(RangeError::InconsistentRangeConstraint);
        }

        Ok(())
    }

    pub fn open_commitment(
        &self,
        pedersen_params: &PedersenParameters<G2Projective, 1>,
        bf: BlindingFactor,
        number: i64,
    ) -> bool {
        self.proof.commitment().verify_opening(
            pedersen_params,
            bf,
            &Message::from(Scalar::from(number as u64)),
        )
    }
}
