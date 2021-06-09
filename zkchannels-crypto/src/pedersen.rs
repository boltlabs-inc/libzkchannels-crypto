//! Pedersen commitments \[1\] over the prime-order pairing groups from BLS12-381 \[2\].
//!
//! ## References
//!
//! 1. Torben Pyrds Pedersen. "Non-interactive and information-theoretic secure verifiable secret
//!    sharing". 1992. URL: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
//!
//! 2. D. Boneh, S. Gorbunov, R. Wahby, H. Wee, and Z. Zhang. "BLS Signatures, Version 4".
//!    Internet-draft, IETF. 2021. URL:
//!    https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04

use crate::{common::*, serde::*, Error};
use arrayvec::ArrayVec;
use group::Group;
use serde::*;
use std::iter;

/// A Pedersen commitment to a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound = "G: SerializeElement")]
pub struct Commitment<G>(#[serde(with = "SerializeElement")] pub(crate) G)
where
    G: Group<Scalar = Scalar>;

/// Parameters for Pedersen commitments.
///
/// These are defined over the prime-order pairing groups from BLS12-381.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "G: SerializeG1")]
pub struct PedersenParameters<G, const N: usize>
where
    G: Group<Scalar = Scalar>,
{
    #[serde(with = "SerializeElement")]
    pub(crate) h: G,
    #[serde(with = "SerializeElement")]
    pub(crate) gs: [G; N],
}

impl<G: Group<Scalar = Scalar>, const N: usize> PedersenParameters<G, N> {
    /// Generate a new set of parameters for making commitments to messages of given
    /// length.
    ///
    /// These are chosen uniformly at random, such that no discrete logarithm relationships
    /// are known among the generators.
    pub fn new(rng: &mut impl Rng) -> Self {
        let h: G = random_non_identity(&mut *rng);
        let gs = iter::repeat_with(|| random_non_identity(&mut *rng))
            .take(N)
            .collect::<ArrayVec<_, N>>()
            .into_inner()
            .expect("length mismatch impossible");
        Self { h, gs }
    }

    /// Commit to a message using the provided blinding factor.
    pub fn commit(&self, msg: &Message<N>, bf: BlindingFactor) -> Result<Commitment<G>, Error> {
        if msg.len() != self.gs.len() {
            return Err(Error::MessageLengthMismatch {
                expected: self.gs.len(),
                got: msg.len(),
            });
        }

        let com: G = self.h * bf.0
            + self
                .gs
                .iter()
                .zip(msg.iter())
                .map(|(&g, m)| g * m)
                .sum::<G>();

        Ok(Commitment(com))
    }

    /// Verify a commitment to a message, using the given blinding factor
    pub fn decommit(
        &self,
        msg: &Message<N>,
        bf: BlindingFactor,
        com: Commitment<G>,
    ) -> Result<bool, Error> {
        Ok(self.commit(msg, bf)? == com)
    }
}
