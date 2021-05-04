/// Implements the commitment scheme from Torben Pryds Pedersen's 1992 paper,
/// "Non-interactive and information-theoretic secure verifiable secret sharing"
/// Available at: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
use crate::types::*;
use group::Group;
use rand::CryptoRng;
use rand_core::RngCore;

/// Represents a Pedersen commitment to a message
#[derive(Debug, Clone)]
pub struct Commitment;

#[derive(Debug, Clone, Copy)]
pub struct CommitmentRandomness(pub Scalar);

impl CommitmentRandomness {
    /// Creates suitably random commitment randomness
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}

#[allow(unused)]
/// Parameters for Pedersen commitments
/// These must be defined over a suitable group.
/// The group must support scalar multiplication and addition over elements, and generation of random values
/// In practice, this should only be used with the groups G1Projective and G2Projective from BLS12-381
pub struct PedersenParameters<T>
where
    T: Group<Scalar = Scalar>,
{
    h: T,
    gs: Vec<T>,
}

impl<T: Group<Scalar = Scalar>> PedersenParameters<T> {
    /// Generates random, new parameters for commitments to messages of given length
    pub fn new(_length: usize, _rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }

    /// Commits to a message using the provided commitment randomness
    pub fn commit(&self, _msg: &Message, _cr: &CommitmentRandomness) -> Commitment {
        todo!();
    }

    /// Verifies the commitment on the given message and randomness
    pub fn decommit(&self, _com: &Commitment, _msg: &Message, _cr: &CommitmentRandomness) -> bool {
        todo!();
    }
}
