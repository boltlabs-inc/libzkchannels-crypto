/*!
Implements Pedersen commitments \[1\] over the prime-order pairing groups from BLS12-381 \[2\].

## References

1. Torben Pyrds Pedersen. "Non-interactive and information-theoretic secure verifiable secret sharing".
1992. URL: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF

2. D. Boneh, S. Gorbunov, R. Wahby, H. Wee, and Z. Zhang. "BLS Signatures, Version 4". Internet-draft, IETF.
2021. URL: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
*/
use crate::{challenge::ChallengeScalar, types::*};
use ff::Field;
use group::Group;
use std::iter;

/// A Pedersen commitment to a message.
#[derive(Debug, Clone, Copy)]
pub struct Commitment<G: Group<Scalar = Scalar>>(pub G);

/// Represents a proof of knowledge of the opening of a commitment.
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
        challenge: Scalar,
    ) -> bool {
        // [c*bf + cs0]h + [c * m1 + cs1]g1 + ...
        let rhs = params.commit(
            &Message::new(self.response_scalars[1..].to_owned()),
            CommitmentRandomness(self.response_scalars[0]),
        );
        let lhs = self.scalar_commitment.0 + (commitment.0 * challenge);
        rhs.0 == lhs
    }
}

/// Represents a partially-built [`CommitmentProof`].
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
    pub fn generate_commitment_phase_objects(
        rng: &mut dyn Rng,
        maybe_commitment_scalars: &[Option<Scalar>],
        params: &PedersenParameters<G>,
    ) -> Self {
        assert_eq!(params.gs.len(), maybe_commitment_scalars.len());

        // Choose commitment scalars and commit to them
        let commitment_scalars = iter::once(Scalar::random(&mut *rng))
            .chain(
                maybe_commitment_scalars
                    .iter()
                    .map(|&maybe_scalar| maybe_scalar.unwrap_or_else(|| Scalar::random(&mut *rng))),
            )
            .collect::<Vec<_>>();

        let scalar_commitment = params.commit(
            &Message::new(commitment_scalars[1..].to_owned()),
            CommitmentRandomness(commitment_scalars[0]),
        );

        Self {
            scalar_commitment,
            commitment_scalars,
        }
    }

    /// Run the challenge and response phases of the Schnorr-style commitment proof to complete the proof.
    pub fn generate_proof_object(
        self,
        msg: &Message,
        commitment_randomness: CommitmentRandomness,
        challenge_scalar: ChallengeScalar,
    ) -> CommitmentProof<G> {
        // generate response scalars
        let response_scalars = iter::once(&commitment_randomness.0)
            .chain(&**msg)
            .zip(&*self.commitment_scalars)
            .map(|(mi, cs)| challenge_scalar.0 * mi + cs)
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

/// Randomness used to construct an information-theoretically hiding commitment.
#[derive(Debug, Clone, Copy)]
pub struct CommitmentRandomness(pub Scalar);

impl CommitmentRandomness {
    /// Choose commitment randomness uniformly at random from the set of possible scalars.
    pub fn new(rng: &mut impl Rng) -> Self {
        Self(Scalar::random(rng))
    }
}

#[allow(unused)]
/// Parameters for Pedersen commitments.
///
/// These are defined over the prime-order pairing groups from BLS12-381.
#[derive(Debug)]
pub struct PedersenParameters<G>
where
    G: Group<Scalar = Scalar>,
{
    h: G,
    gs: Vec<G>,
}

impl<G: Group<Scalar = Scalar>> PedersenParameters<G> {
    /**
    Generate a new set of parameters for making commitments to messages of given
    length.

    These are chosen uniformly at random, such that no discrete logarithm relationships
    are known among the generators.
    */
    pub fn new(_length: usize, _rng: &mut impl Rng) -> Self {
        todo!();
    }

    /// Commit to a message using the provided commitment randomness.
    pub fn commit(&self, _msg: &Message, _cr: CommitmentRandomness) -> Commitment<G> {
        todo!();
    }

    /// Verify a commitment to a message, using the given commitment randomness scalar.
    pub fn decommit(&self, _com: Commitment<G>, _msg: &Message, _cr: CommitmentRandomness) -> bool {
        todo!();
    }
}
