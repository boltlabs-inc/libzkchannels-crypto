/*!
Implementation of proofs of knowledge of the opening of a Pedersen commitment.

These are Schnorr zero-knowledge proofs that use a commitment and response phase to show
that the prover knows the opening of a commitment, without revealing the underlying [`Message`].

## Intuition
This implements the original Schnorr protocol \[1\], leaving the challenge phase undefined.

The protocol has three phases.
1. *Commit*. The prover chooses a random mask for each block in the message (as well as for the commitment randomness).
They form a commitment to this randomness with the same parameters that were used to form the original commitment.
The output of this step is described by [`CommitmentProofBuilder`].

2. *Challenge*. The prover obtains a random challenge. There are several acceptable ways to generate this; see [`Challenge`] for details.

3. *Response*. The prover constructs masked versions of each message block, incorporating the commitment randomness and the challenge.

The [`CommitmentProof`] consists of the commitment to randomness and the masked responses.

Given the proof and the commitment, the verifier checks the consistency of the commitment (to the original message), the commitment to randomness,
the challenge, and the responses. The protocol promises that a malicious prover cannot produce a consistent set of objects without knowing the underlying
message.

## References
1. C. P. Schnorr. Efficient signature generation by smart cards. Journal of Cryptology, 4(3):161–174, Jan 1991.

*/
use crate::{challenge::Challenge, pedersen_commitments::*, types::*};
use group::Group;
use std::iter;

/// Fully constructed proof of knowledge of the opening of a commitment.
#[derive(Debug, Clone)]
pub struct CommitmentProof<G: Group<Scalar = Scalar>> {
    /// The commitment to the commitment scalars.
    pub scalar_commitment: Commitment<G>,
    /// The response scalars, with the blinding factor prepended.   
    response_scalars: Vec<Scalar>,
}

impl<G: Group<Scalar = Scalar>> CommitmentProof<G> {
    /// Verify knowledge of the opening of a commitment.
    pub fn verify_knowledge_of_opening_of_commitment(
        &self,
        _params: &PedersenParameters<G>,
        _commitment: Commitment<G>,
        _challenge: Challenge,
    ) -> bool {
        todo!();
    }

    /// Get the response scalars of this commitment proof corresponding to the message (e.g. not including the blinding factor)
    pub fn response_scalars(&self) -> &[Scalar] {
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
    /// The commitment scalars, with the blinding factor prepended.
    commitment_scalars: Vec<Scalar>,
}

impl<G: Group<Scalar = Scalar>> CommitmentProofBuilder<G> {
    /**
    Run the commitment phase of a Schnorr-style commitment proof.

    The `maybe_commitment_scalars` argument allows the caller to choose particular commitment
    scalars in the case that they need to satisfy some sort of constraint, for example when
    implementing equality or linear combination constraints on top of the proof.
    */
    pub fn generate_proof_commitments(
        _rng: &mut dyn Rng,
        _maybe_commitment_scalars: &[Option<Scalar>],
        _params: &PedersenParameters<G>,
    ) -> Self {
        todo!();
    }

    /// Get the commitment scalars corresponding to the message (e.g. not including the scalar corresponding to the blinding factor)
    pub fn commitment_scalars(&self) -> &[Scalar] {
        &self.commitment_scalars[1..]
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
    }
}
