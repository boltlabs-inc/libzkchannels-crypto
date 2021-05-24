/*!
Cryptographic functionality for the establish protocol as described in zkAbacus.

This *does not* perform checks that new channel requests are actually fresh. This **must** be done
outside this module.

*/
use crate::states::*;
use crate::{
    merchant::{Output, Ready},
    proofs::EstablishProof,
};

impl Ready {
    /// Instantiate a new merchant in the `Ready` state.
    pub fn new() -> Self {
        todo!();
    }

    /// Respond to a customer request to initialize a new channel.
    ///
    /// Fails in the case where the given [`EstablishProof`] does not verify with respect to the public variables.
    ///
    /// The given `channel_id` *must* be fresh.
    ///
    /// @Kenny: there are two "sets" of inputs here. Channel id + balances are public inputs, should be agreed on
    /// before receiving the commitments + proof. I think the public inputs should be received and stored, then
    /// retrieved on receipt of the commitments (they will have to provide a cid with the commitments + proof)
    /// Also, on receipt of the commitments, the caller function should first check that the cid has not been seen before.
    pub fn initialize(
        &self,
        _channel_id: ChannelId,
        _customer_balance: CustomerBalance,
        _merchant_balance: MerchantBalance,
        _close_state_commitment: CloseStateCommitment,
        _state_commitment: StateCommitment,
        _proof: EstablishProof,
    ) -> Result<Output<Ready, (ChannelId, StateCommitment), CloseStateBlindedSignature>, String>
    {
        todo!();
    }

    /// Respond to a customer request to activate a channel.
    pub fn activate(&self, _channel_id: ChannelId, _state_commitment: StateCommitment) {
        todo!();
    }
}
