/*!
Proofs of knowledge of an opening of a Pedersen commitment.

These are Schnorr zero-knowledge proofs that use a commitment and response phase to show
that the prover knows an opening of a commitment, without revealing the underlying [`Message`].

## Intuition
This implements the original Schnorr protocol \[1\], leaving the challenge phase undefined.

The protocol has three phases.
1. *Commit*. The prover chooses random commitment scalars for each message in the tuple and the
    commitment randomness. They
    form a commitment to this randomness with the same parameters that were used to form the
    original commitment. The output of this step is described by [`CommitmentProofBuilder`].

2. *Challenge*. In an interactive proof, the prover obtains a random challenge from the verifier.
    However, it is standard practice to use the Fiat-Shamir heuristic to transform an interactive
    proof into a non-interactive proof; see [`Challenge`] for details.

3. *Response*. The prover constructs response scalars, which mask each element of the message tuple
    and the blinding factor with the corresponding commitment scalar and the challenge.

The [`CommitmentProof`] consists of the commitment to the commitment scalars and the response
scalars.

Given the proof and the commitment, the verifier checks the consistency of the commitment (to the
original message), the commitment to randomness, the challenge, and the responses. A malicious
prover cannot produce a consistent set of objects without knowing the underlying message and
blinding factor.

## References
1. C. P. Schnorr. Efficient signature generation by smart cards. Journal of Cryptology,
    4(3):161–174, Jan 1991.

*/
use crate::{challenge::Challenge, pedersen_commitments::*, types::*};
use ff::Field;
use group::Group;
use std::iter;

/// Fully constructed proof of knowledge of the opening of a commitment.
#[derive(Debug, Clone)]
pub struct CommitmentProof<G: Group<Scalar = Scalar>> {
    /// The commitment to the commitment scalars.
    pub scalar_commitment: Commitment<G>,
    /// The response scalars, with the response scalar for the blinding factor prepended.
    response_scalars: Vec<Scalar>,
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
            BlindingFactor(self.response_scalars[0]),
        );

        // Compare to challenge, commitments to message, scalars
        let lhs = self.scalar_commitment.0 + (commitment.0 * challenge.0);
        rhs.0 == lhs
    }

    /// Get the response scalars corresponding to the message to verify conjunctions of proofs.
    ///
    /// This does not include the response scalar for the blinding factor.
    pub fn conjunction_response_scalars(&self) -> &[Scalar] {
        &self.response_scalars[1..]
    }
}

/**
A partially-built [`CommitmentProof`].

Built up to (but not including) the challenge phase of a Schnorr proof.
*/
#[derive(Debug, Clone)]
pub struct CommitmentProofBuilder<G: Group<Scalar = Scalar>> {
    /// Commitment to the commitment scalars.
    pub scalar_commitment: Commitment<G>,
    /// The commitment scalars for the blinding factor and message (in that order).
    commitment_scalars: Vec<Scalar>,
}

impl<G: Group<Scalar = Scalar>> CommitmentProofBuilder<G> {
    /**
    Run the commitment phase of a Schnorr-style commitment proof.

    The `conjunction_commitment_scalars` argument allows the caller to choose particular commitment
    scalars in the case that they need to satisfy some sort of constraint, for example when
    implementing equality or linear combination constraints on top of the proof.
    */
    pub fn generate_proof_commitments(
        rng: &mut dyn Rng,
        conjunction_commitment_scalars: &[Option<Scalar>],
        params: &PedersenParameters<G>,
    ) -> Self {
        assert_eq!(params.message_len(), conjunction_commitment_scalars.len());

        // Choose commitment scalars (that haven't already been specified)
        let commitment_scalars = iter::once(Scalar::random(&mut *rng))
            .chain(
                conjunction_commitment_scalars
                    .iter()
                    .map(|&maybe_scalar| maybe_scalar.unwrap_or_else(|| Scalar::random(&mut *rng))),
            )
            .collect::<Vec<_>>();

        // Commit to the scalars
        let scalar_commitment = params.commit(
            &Message::new(commitment_scalars[1..].to_owned()),
            BlindingFactor(commitment_scalars[0]),
        );

        Self {
            scalar_commitment,
            commitment_scalars,
        }
    }

    /// Get the commitment scalars corresponding to the message tuple to use when constructing
    /// conjunctions of proofs.
    ///
    /// This does not include the commitment scalar corresponding to the blinding factor.
    pub fn conjunction_commitment_scalars(&self) -> &[Scalar] {
        &self.commitment_scalars[1..]
    }

    /// Run the response phase of the Schnorr-style commitment proof to complete the proof.
    pub fn generate_proof_response(
        self,
        msg: &Message,
        blinding_factor: BlindingFactor,
        challenge: Challenge,
    ) -> CommitmentProof<G> {
        // Generate response scalars.
        let response_scalars = iter::once(&blinding_factor.0)
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
