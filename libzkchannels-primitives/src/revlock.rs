use crate::parameters::*;
use crate::types::*;
use pedersen_commitments::*;

pub struct RevocationLock;

pub struct RevocationSecret;

pub fn generate_revocation_pair(
    _rng: &mut (impl CryptoRng + RngCore),
) -> (RevocationLock, RevocationSecret) {
    todo!();
}

pub struct RevocationLockCommitment(Commitment);

impl RevocationLock {
    /// Forms a commitment (and corresponding commitment randomness) to a RevocationLock
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (RevocationLockCommitment, CommitmentRandomness) {
        todo!();
    }
}
