use crate::types::*;

#[derive(Debug, Clone, Copy)]
pub struct CommitmentRandomness(pub Scalar);

struct Commitment;

impl Commitment {
    /// Commits to a message; produces commitment and commitment randomness
    pub fn commit(_rng: &mut (impl CryptoRng + RngCore), _msg: &Message) 
    -> (Commitment, CommitmentRandomness) 
    {
        todo!();
    }

    /// verifies the commitment on the given message and randomness
    pub fn decommit(&self, msg: &Message, r: &CommitmentRandomness) -> bool {
        todo!();
    }
}