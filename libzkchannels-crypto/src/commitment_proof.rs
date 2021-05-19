//! Create and verify proofs of knowledge of the opening of a Pedersen commitment.
use crate::{challenge::Challenge, pedersen_commitments::*, types::*};
use ff::Field;
use group::Group;
use std::iter;

/// Fully constructed proof of knowledge of the opening of a commitment.
#[derive(Debug, Clone)]
pub struct CommitmentProof<G: Group<Scalar = Scalar>> {
    /// The commitment to the commitment scalars.
    pub scalar_commitment: Commitment<G>,
    /// The response scalars.   
    pub response_scalars: Vec<Scalar>,
}

impl<G: Group<Scalar = Scalar>> CommitmentProof<G> {
    /// Verify knowledge of the opening of a commitment.
    pub fn verify_knowledge_of_opening_of_commitment(
        &self,
        params: &PedersenParameters<G>,
        commitment: Commitment<G>,
        challenge: Challenge,
    ) -> bool {
        // Construct commitment to response scalars.
        // [c*bf + cs0]h + [c * m1 + cs1]g1 + ...
        let rhs = params.commit(
            &Message::new(self.response_scalars[1..].to_owned()),
            CommitmentRandomness(self.response_scalars[0]),
        );

        // Compare to challenge, commitments to message, scalars
        let lhs = self.scalar_commitment.0 + (commitment.0 * challenge.0);
        rhs.0 == lhs
    }
}

/// A partially-built [`CommitmentProof`].
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct CommitmentProofBuilder<G: Group<Scalar = Scalar>> {
    /// Commitment to the commitment scalars.
    pub scalar_commitment: Commitment<G>,
    /// The commitment scalars.
    pub commitment_scalars: Vec<Scalar>,
}

impl<G: Group<Scalar = Scalar>> CommitmentProofBuilder<G> {
    /// Run the commitment phase of a Schnorr-style commitment proof.
    ///
    /// The `maybe_commitment_scalars` argument allows the caller to choose particular commitment
    /// scalars in the case that they need to satisfy some sort of constraint, for example when
    /// implementing equality or linear combination constraints on top of the proof.
    pub fn generate_proof_commitments(
        rng: &mut dyn Rng,
        maybe_commitment_scalars: &[Option<Scalar>],
        params: &PedersenParameters<G>,
    ) -> Self {
        assert_eq!(params.message_len(), maybe_commitment_scalars.len());

        // Choose commitment scalars (that haven't already been specified)
        let commitment_scalars = iter::once(Scalar::random(&mut *rng))
            .chain(
                maybe_commitment_scalars
                    .iter()
                    .map(|&maybe_scalar| maybe_scalar.unwrap_or_else(|| Scalar::random(&mut *rng))),
            )
            .collect::<Vec<_>>();

        // Commit to the scalars
        let scalar_commitment = params.commit(
            &Message::new(commitment_scalars[1..].to_owned()),
            CommitmentRandomness(commitment_scalars[0]),
        );

        Self {
            scalar_commitment,
            commitment_scalars,
        }
    }

    /// Run the response phase of the Schnorr-style commitment proof to complete the proof.
    pub fn generate_proof_response(
        self,
        msg: &Message,
        commitment_randomness: CommitmentRandomness,
        challenge: Challenge,
    ) -> CommitmentProof<G> {
        // Generate response scalars.
        let response_scalars = iter::once(&commitment_randomness.0)
            .chain(&**msg)
            .zip(&*self.commitment_scalars)
            .map(|(mi, cs)| challenge.0 * mi + cs)
            .collect::<Vec<_>>();

        CommitmentProof {
            scalar_commitment: self.scalar_commitment,
            response_scalars,
        }

        /*
            [bf]*h + [m1]*g1 + ... + [ml]*gl        <-- original commitment

            [cs0]*h + [cs1]*g1 + ... + [csl]*gl     <-- scalar commitment

            c * bf + cs0, c * m1 + cs1, ...         <-- response scalars - ties together two commitment values!

        */
    }
}
