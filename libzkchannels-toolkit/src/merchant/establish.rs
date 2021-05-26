/*!
Cryptographic functionality for the establish protocol as described in zkAbacus.

This *does not* perform checks that new channel requests are actually fresh. This **must** be done
outside this module.

*/
use crate::states::*;
use crate::{merchant::Config, proofs::EstablishProof};

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    /// Instantiate a new merchant with all parameters.
    pub fn new() -> Self {
        todo!();
    }

    /**
    Respond to a customer request to initialize a new channel.

    Fails in the case where the given [`EstablishProof`] does not verify with respect to the
    public variables (channel id, balances, and provided commitments).

    The given `channel_id` *must* be fresh; this should only be called if the [`ChannelId`] has
    never been seen before.

    Note: there are two "flavors" of inputs here. Channel id + balances are public inputs, should
    be agreed on outside of zkAbacus. The commitments + proof are received from the customer.
    */
    pub fn initialize(
        &self,
        _channel_id: &ChannelId,
        _customer_balance: CustomerBalance,
        _merchant_balance: MerchantBalance,
        _state_commitment: &StateCommitment,
        _close_state_commitment: CloseStateCommitment,
        _proof: EstablishProof,
    ) -> Option<CloseStateBlindedSignature> {
        todo!();
    }

    /**
    Respond to a customer request to activate a channel.

    This should only be called if the [`ChannelId`] is stored in the merchant database with
    this [`StateCommitment`].
    */
    pub fn activate(
        &self,
        _channel_id: &ChannelId,
        _state_commitment: &StateCommitment,
    ) -> BlindedPayToken {
        todo!();
    }
}
