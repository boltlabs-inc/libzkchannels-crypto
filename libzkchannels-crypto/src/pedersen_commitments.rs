/// Implements the commitment scheme from Torben Pryds Pedersen's 1992 paper,
/// "Non-interactive and information-theoretic secure verifiable secret sharing"
/// Available at: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
use crate::types::*;
use rand::CryptoRng;
use rand_core::RngCore;

/// Commitment object
#[derive(Debug, Clone)]
pub struct Commitment;

/// Commitment randomness (generated during commitment)
#[derive(Debug, Clone, Copy)]
pub struct CommitmentRandomness(pub Scalar);

impl CommitmentRandomness {
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}

/// Parameters for Pedersen commitments
pub struct PedersenParameters;

impl PedersenParameters {
    /// Generates new generators to use in Pedersen commitments
    pub fn new(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        todo!();
    }
}

impl Message {
    /// Commits to a message; produces commitment and commitment randomness
    pub fn commit(&self, _cr: &CommitmentRandomness, _pp: &PedersenParameters) -> Commitment {
        todo!();
    }

    /// Verifies the commitment on the given message and randomness
    pub fn decommit(
        &self,
        _pp: &PedersenParameters,
        _com: &Commitment,
        _r: &CommitmentRandomness,
    ) -> bool {
        todo!();
    }
}
