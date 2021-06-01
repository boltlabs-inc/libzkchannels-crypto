/*!
Pedersen commitments \[1\] over the prime-order pairing groups from BLS12-381 \[2\].

## References

1. Torben Pyrds Pedersen. "Non-interactive and information-theoretic secure verifiable secret sharing".
1992. URL: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF

2. D. Boneh, S. Gorbunov, R. Wahby, H. Wee, and Z. Zhang. "BLS Signatures, Version 4". Internet-draft, IETF.
2021. URL: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
*/
use crate::{serde::*, types::*};
use group::Group;
use serde::*;

/// A Pedersen commitment to a message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound = "G: SerializeElement")]
pub struct Commitment<G>(#[serde(with = "SerializeElement")] G)
where
    G: Group<Scalar = Scalar>;

/// Parameters for Pedersen commitments.
///
/// These are defined over the prime-order pairing groups from BLS12-381.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "G: SerializeG1")]
pub struct PedersenParameters<G>
where
    G: Group<Scalar = Scalar>,
{
    #[serde(with = "SerializeElement")]
    h: G,
    #[serde(with = "SerializeElement")]
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

    /// Commit to a message using the provided blinding factor.
    pub fn commit(&self, _msg: &Message, _bf: BlindingFactor) -> Commitment<G> {
        todo!();
    }

    /// Verify a commitment to a message, using the given blinding factor
    pub fn decommit(&self, _com: Commitment<G>, _msg: &Message, _bf: BlindingFactor) -> bool {
        todo!();
    }

    /// Return the message length that these parameters can commit to.
    pub fn message_len(&self) -> usize {
        self.gs.len()
    }
}
