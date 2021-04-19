use crate::{blinded_signatures::*, types::*};
use rand::CryptoRng;
use rand_core::RngCore;

/// Commitment object
#[derive(Debug, Clone)]
pub struct Commitment;

/// Commitment randomness (generated during commitment)
#[derive(Debug, Clone, Copy)]
pub struct CommitmentRandomness(pub Scalar);

trait Commit {
    /// Commits to a message; produces commitment and commitment randomness
    fn commit(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> (Commitment, CommitmentRandomness);

    /// Verifies the commitment on the given message and randomness
    fn decommit(&self, msg: &Message, com: Commitment, r: &CommitmentRandomness) -> bool;
}

/// Pedersen commitment using generators defined in a Pointcheval-Sanders public key
impl Commit for BlindPublicKey {
    fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _msg: &Message,
    ) -> (Commitment, CommitmentRandomness) {
        todo!();
    }

    fn decommit(&self, _msg: &Message, _com: Commitment, _r: &CommitmentRandomness) -> bool {
        todo!();
    }
}

/// Pedersen commitment using generators defined in a Pointcheval-Sanders keypair
impl Commit for BlindKeyPair {
    fn commit(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &Message,
    ) -> (Commitment, CommitmentRandomness) {
        self.pk.commit(rng, msg)
    }

    fn decommit(&self, msg: &Message, com: Commitment, r: &CommitmentRandomness) -> bool {
        self.pk.decommit(msg, com, r)
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

/// General-purpose Pedersen commitments
impl Commit for PedersenParameters {
    fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _msg: &Message,
    ) -> (Commitment, CommitmentRandomness) {
        todo!();
    }

    fn decommit(&self, _msg: &Message, _com: Commitment, _r: &CommitmentRandomness) -> bool {
        todo!();
    }
}
