/*!
Implements Pedersen commitments \[1\] over the prime-order pairing groups from BLS12-381 \[2\].

## References

1. Torben Pyrds Pedersen. "Non-interactive and information-theoretic secure verifiable secret sharing".
1992. URL: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF

2. D. Boneh, S. Gorbunov, R. Wahby, H. Wee, and Z. Zhang. "BLS Signatures, Version 4". Internet-draft, IETF.
2021. URL: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
*/
use crate::types::*;
use ff::Field;
use group::Group;

/// A Pedersen commitment to a message.
#[derive(Debug, Clone, Copy)]
pub struct Commitment<G: Group<Scalar = Scalar>>(pub G);

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

    /// Return the message length that these parameters can commit to.
    pub fn message_len(&self) -> usize {
        self.gs.len()
    }
}
