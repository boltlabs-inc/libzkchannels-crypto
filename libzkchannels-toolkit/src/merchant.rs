//! Cryptographic routines to establish a new merchant, establish customer channels, and
//! process payments.

use crate::{
    nonce::Nonce,
    proofs::{EstablishProof, PayProof},
    revlock::*,
    states::*,
    states::{CloseStateCommitment, StateCommitment},
};

/// A merchant that is ready to establish channels and process payments.
///
/// Holds keys and parameters used throughout the lifetime of a merchant node, across
/// all its zkChannels.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct Config;

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
    public variables (channel ID, balances, and provided commitments).

    The given `channel_id` *must* be fresh; this should only be called if the [`ChannelId`] has
    never been seen before.

    Note: there are two "flavors" of inputs here. Channel ID + balances are public inputs, should
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
    ) -> Option<crate::ClosingSignature> {
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
    ) -> crate::PayToken {
        todo!();
    }

    /**
    On receiving a payment request, issue a [`ClosingSignature`](crate::ClosingSignature) on the
    updated state, if the provided evidence is valid.

    This should only be called if the [`Nonce`] has never been seen before.

    This will fail if the [`PayProof`] is not verifiable with the provided commitments and
    [`Nonce`].
    */
    pub fn allow_payment<'a>(
        &'a self,
        _nonce: &Nonce,
        _pay_proof: PayProof,
        _revocation_commitment: RevocationLockCommitment,
        _state_commitment: StateCommitment,
        _close_state_commitment: CloseStateCommitment,
    ) -> Option<(Unrevoked<'a>, crate::ClosingSignature)> {
        todo!();
    }
}
/// A merchant that has approved a new payment on a channel, but has not revoked the previous
/// channel state.
#[derive(Debug)]
pub struct Unrevoked<'a> {
    config: &'a Config,
    revocation_commitment: RevocationLockCommitment,
    state_commitment: StateCommitment,
}

impl<'a> Unrevoked<'a> {
    /**
    Complete a payment by issuing a pay token on the updated state, if the revocation information
    is well-formed.

    This should only be called if the revocation lock has never been seen before.

    This will fail if the revocation information is not well-formed (e.g. the revocation lock does
    not match the revocation secret; or it does not match the stored revocation commitment).
    */
    pub fn revoke(
        self,
        _revocation_lock: &RevocationLock,
        _revocation_secret: &RevocationSecret,
        _revocation_blinding_factor: &RevocationLockBlindingFactor,
    ) -> Result<crate::PayToken, Unrevoked<'a>> {
        todo!();
    }
}
