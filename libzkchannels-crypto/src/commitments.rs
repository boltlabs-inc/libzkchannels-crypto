use crate::{blinded_signatures::BlindPublicKey, types::*};
use rand::CryptoRng;
use rand_core::RngCore;

/// Commitment object
#[derive(Debug, Clone)]
pub struct Commitment;

/// Commitment randomness (generated during commitment)
#[derive(Debug, Clone, Copy)]
pub struct CommitmentRandomness(pub Scalar);

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
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _pp: &PedersenParameters,
    ) -> (Commitment, CommitmentRandomness) {
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

    /// Commits to a message using generators from a Pointcheval-Sanders key
    pub fn commit_to_publickey(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _pk: &BlindPublicKey,
    ) -> (Commitment, CommitmentRandomness) {
        todo!();
    }

    /// Verifies a commitment with randomness generated with the public key
    pub fn decommit_to_publickey(
        &self,
        _pk: &BlindPublicKey,
        _com: &Commitment,
        _r: &CommitmentRandomness,
    ) -> bool {
        todo!();
    }
}
