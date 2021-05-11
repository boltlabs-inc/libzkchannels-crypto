//! This describes the proof used in the Pay subprotocol of libzkchannels.
//! 
//! This is a Schnorr proof that makes the following guarantees in zero knowledge:
//! - The old state is correctly updated from the new state by the given payment amount.
//! - The customer holds a valid [`PayToken`](crate::states::PayToken) and knows the old [`State`] it corresponds to.
//! - The customer knows the opening of commitments to the [`RevocationLock`], 
//! the new [`State`], and the corresponding `CloseState`. 
//! - The committed [`RevocationLock`] and revealed [`Nonce`] are contained in the old [`State`].
//! - The balances in the new [`State`] are non-negative.
use serde::*;

use crate::nonce::*;
use crate::parameters::*;
use crate::revlock::*;
use crate::states::*;
use crate::types::*;

/// Payment proof: provides proof that a party has a new state that is correctly updated
/// from a previous state, for which it holds a signature.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayProof;

impl PayProof {
    /// Forms a new zero-knowledge PayProof object.
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

    /// Verifies a PayProof of knowledge of opening of commitments with the given public parameters (nonce, amount).
    pub fn verify(
        &self,
        _params: &MerchantParameters,
        _verification_objects: &PayProofVerification,
    ) -> bool {
        todo!();
    }
}

/// Collects the information a merchant needs to verify a [`PayProof`].
#[derive(Debug, Clone, Copy)]
pub struct PayProofVerification {
    /// Blinded, unused pay token from the merchant.
    pub _pay_token: BlindedPayToken,
    /// Commitment to an unused pay token.
    pub _pay_token_com: PayTokenCommitment,
    /// Commitment to the revocation lock in the old state.
    pub _rl_com: RevocationLockCommitment,
    /// Commitment to the new channel state.
    pub _state_com: StateCommitment,
    /// Commitment to the new close state.
    pub _close_state_com: CloseStateCommitment,
    /// Public nonce revealed at the beginning of Pay.
    pub _nonce: Nonce,
    /// Public payment amount.
    pub _amount: PaymentAmount,
}