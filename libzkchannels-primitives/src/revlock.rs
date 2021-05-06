use crate::parameters::*;
use crate::types::*;
use pedersen_commitments::*;

pub struct RevocationLock;

pub struct RevocationSecret;

pub struct RevocationLockCommitment(Commitment);

pub struct RevocationLockCommitmentRandomness();

impl RevocationLock {
    /// Generates a new revocation lock and its corresponding secret
    pub fn generate_pair(_rng: &mut (impl CryptoRng + RngCore)) -> (Self, RevocationSecret) {
        todo!();
    }

    /// Validates a revocation pair
    pub fn verify(&self, _rs: &RevocationSecret) -> bool {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to a RevocationLock
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (RevocationLockCommitment, RevocationLockCommitmentRandomness) {
        todo!();
    }
}

impl RevocationLockCommitment {
    /// validates commitment to revocation lock
    pub fn decommit(
        &self,
        _param: &MerchantParameters,
        _rl: &RevocationLock,
        _bf: &RevocationLockCommitmentRandomness,
    ) -> bool {
        todo!();
    }
}
