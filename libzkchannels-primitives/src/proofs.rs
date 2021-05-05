use crate::parameters::*;
use crate::revlock::*;
use crate::states::*;
use crate::types::*;

/// Payment proof: provides proof that a party has a new state that is correctly updated
/// from a previous state, for which it holds a signature.
pub struct PayProof;

impl PayProof {
    /// Forms a new PayProof: commits to revocation lock, old state, and two new states
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _params: &CustomerParameters,
        _rl: &RevocationLock,
        _old_state: &State,
        _state: &State,
        _close_state: &CloseState,
    ) -> (
        Self,
        RevocationLockCommitment,
        StateCommitment,
        CloseStateCommitment,
    ) {
        todo!();
    }

    pub fn verify(_params: &MerchantParameters) -> bool {
        todo!();
    }
}
