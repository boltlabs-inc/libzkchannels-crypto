//! Implements Pedersen commitments in a prime order group.
//!
//! This commitment scheme is from Torben Pryds Pedersen's 1992 paper,
//! "Non-interactive and information-theoretic secure verifiable secret sharing"
//! Available at: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF .*/
use crate::types::*;
use group::Group;
use rand::CryptoRng;
use rand_core::RngCore;

/// Represents a Pedersen commitment to a message.
#[derive(Debug, Clone)]
pub struct Commitment;

/// Randomness used to construct an information-theoretically hiding commitment.
#[derive(Debug, Clone, Copy)]
pub struct CommitmentRandomness(pub Scalar);

impl CommitmentRandomness {
    /// Creates suitably random commitment randomness.
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}

#[allow(unused)]
/// Parameters for Pedersen commitments.
/// These must be defined over a suitable group, written additively.
/// In practice, this should only be used with the groups from BLS12-381.
pub struct PedersenParameters<G>
where
    G: Group<Scalar = Scalar>,
{
    h: G,
    gs: Vec<G>,
}

impl<G: Group<Scalar = Scalar>> PedersenParameters<G> {
    /// Generates random, new parameters for commitments to messages of given length.
    pub fn new(_length: usize, _rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }

    /// Commits to a message using the provided commitment randomness.
    pub fn commit(&self, _msg: &Message, _cr: &CommitmentRandomness) -> Commitment {
        todo!();
    }

    /// Verifies the commitment on the given message and randomness.
    pub fn decommit(&self, _com: &Commitment, _msg: &Message, _cr: &CommitmentRandomness) -> bool {
        todo!();
    }
}
