use serde::*;

use crate::nonce::*;
use crate::parameters::*;
use crate::revlock::*;
use crate::states::*;
use crate::types::*;

/// Payment proof: provides proof that a party has a new state that is correctly updated
/// from a previous state, for which it holds a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayProof;

impl PayProof {
    /// Forms a new PayProof: commits to revocation lock, old state, and two new states
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _params: &CustomerParameters,
        _rl: &RevocationLock,
        _old_state: State,
        _old_state_bf: &PayTokenBlindingFactor,
        _state: &State,
    ) -> (
        Self,
        RevocationLockCommitment,
        StateCommitment,
        CloseStateCommitment,
    ) {
        todo!();
    }

    /// Verifies a PayProof of knowledge of opening of commitments with the given public parameters (nonce, amount)
    pub fn verify(
        &self,
        _params: &MerchantParameters,
        _pay_token: &BlindedPayToken,
        _pay_token_com: &PayTokenCommitment,
        _rl_com: &RevocationLockCommitment,
        _state_com: &StateCommitment,
        _close_state_com: &CloseStateCommitment,
        _nonce: &Nonce,
        _amount: &PaymentAmount,
    ) -> bool {
        todo!();
    }
}
