//! Defines various state types used in the libzkchannels protocol.
//!
//! The primary type is a [`State`], which describes a zkChannel at a point in time. This object
//! is operated on throughout the protocol:
//! - A [`PayToken`] is a merchant signature on a [`State`], and allows a customer to continue making payments on a channel.
//! - A `CloseState` is a [`State`] with the payment-specific nonce removed. When signed, it can be used to claim funds on-chain
//! while maintaining payment privacy. To avoid de-synchronizing the `State` and `CloseState`, this library never produces a
//! `CloseState` directly.
//!
use serde::*;

use crate::nonce::*;
use crate::parameters::*;
use crate::revlock::*;
use crate::types::*;
use ps_blind_signatures::*;
use ps_signatures::Signature;

/// Channel identifier, binds each transaction to a specific customer.
#[derive(Debug, Clone, Copy)]
pub struct ChannelId;

/// Channel balance for merchant.
#[derive(Debug, Clone, Copy)]
pub struct MerchantBalance;

/// Channel balance for customer.
#[derive(Debug, Clone, Copy)]
pub struct CustomerBalance;

/// Amount of a single payment.
#[derive(Debug, Clone, Copy)]
pub struct PaymentAmount;

impl PaymentAmount {
    /// Construct a *positive* payment amount from the customer to the merchant.
    pub fn pay_merchant(_amount: usize) -> Self {
        todo!()
    }

    /// Construct a *negative* payment amount from the merchant to the customer (i.e. a refund).
    pub fn pay_customer(_amount: usize) -> Self {
        todo!()
    }
}

/// Describes the complete state of the channel with the given ID.
#[allow(missing_copy_implementations)]
#[derive(Debug, Clone)]
pub struct State {
    channel_id: ChannelId,
    nonce: Nonce,
    revocation_lock: RevocationLock,
    merchant_balance: MerchantBalance,
    customer_balance: CustomerBalance,
}

/// The closing state for a state.
#[derive(Debug, Clone, Copy)]
pub struct CloseState<'a> {
    channel_id: &'a ChannelId,
    revocation_lock: &'a RevocationLock,
    merchant_balance: &'a MerchantBalance,
    customer_balance: &'a CustomerBalance,
}

impl State {
    /// Generates a new `State` with the given balances and ID.
    pub fn new(
        _rng: &mut impl Rng,
        _channel_id: ChannelId,
        _merchant_balance: MerchantBalance,
        _customer_balance: CustomerBalance,
    ) -> Self {
        todo!();
    }

    /// Get the channel ID for this state.
    pub fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    /// Get the merchant's current [`MerchantBalance`] for this state.
    pub fn merchant_balance(&self) -> &MerchantBalance {
        &self.merchant_balance
    }

    /// Get the customer's current [`CustomerBalance] for this state.
    pub fn customer_balance(&self) -> &CustomerBalance {
        &self.customer_balance
    }

    /// Get the current [`RevocationLock`] for this state.
    pub fn revocation_lock(&self) -> &RevocationLock {
        &self.revocation_lock
    }

    /// Get the current [`Nonce`] for this state.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Get the closing state for this state.
    pub fn close_state(&self) -> CloseState<'_> {
        let State {
            channel_id,
            revocation_lock,
            merchant_balance,
            customer_balance,
            ..
        } = self;
        CloseState {
            channel_id,
            revocation_lock,
            merchant_balance,
            customer_balance,
        }
    }

    /// Applies a payment to the state by updating the balances appropriately and generating new
    /// [`Nonce`] and [`RevocationLock`] (returning the corresponding [`RevocationSecret`]).
    ///
    /// A positive payment amount *deducts* from the [`CustomerBalance`] and *adds* to the
    /// [`MerchantBalance`]; a negative payment amount *adds* to the [`CustomerBalance`] and
    /// *deducts* from the [`MerchantBalance`].
    pub fn apply_payment<'a>(
        &'a mut self,
        _rng: &mut impl Rng,
        _amt: &PaymentAmount,
    ) -> Current<'a, RevocationSecret> {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to a `State`.
    pub fn commit<'a>(
        &'a self,
        _rng: &mut impl Rng,
        _param: &CustomerParameters,
    ) -> (
        Current<'a, StateCommitment>,
        Current<'a, PayTokenBlindingFactor>,
    ) {
        todo!();
    }
}

impl CloseState<'_> {
    /// Forms a commitment (and corresponding commitment randomness) to a `CloseState`
    pub fn commit<'a>(
        &'a self,
        _rng: &mut impl Rng,
        _param: &CustomerParameters,
    ) -> (
        Current<'a, CloseStateCommitment>,
        Current<'a, CloseStateBlindingFactor>,
    ) {
        todo!();
    }
}

/// Commitment to a State.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct StateCommitment(/*Commitment*/);

/// Commitment to a CloseState.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateCommitment(/*Commitment*/);

/// Signature on a CloseState - can be posted on-chain to close a channel.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct CloseStateSignature;

/// Blinded signature on a CloseState.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateBlindedSignature;

/// Blinding factor for a [`CloseStateCommitment`] and corresponding [`CloseStateBlindedSignature`].
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct CloseStateBlindingFactor;

impl CloseStateBlindedSignature {
    /// Produces a signed close state so the customer can close a channel.
    ///
    /// This is typically called by the merchant.
    pub fn new(
        _rng: &mut impl Rng,
        _param: &MerchantParameters,
        _com: CloseStateCommitment,
    ) -> CloseStateBlindedSignature {
        todo!();
    }

    /// Unblinds a [`CloseStateBlindedSignature`] to get an (unblinded) [`CloseStateSignature`]
    /// using the given blinding factor.
    ///
    /// This is typically called by the customer.
    pub fn unblind<'a>(
        self,
        _bf: Current<'a, CloseStateBlindingFactor>,
    ) -> Current<'a, CloseStateSignature> {
        todo!();
    }
}

impl CloseStateSignature {
    /// Verifies the merchant signature on a closing state (derived from the given [`CloseState`]).
    ///
    /// This is typically called by the customer.
    pub fn verify(
        &self,
        _param: &CustomerParameters,
        _close_state: CloseState<'_>,
    ) -> Verification {
        todo!();
    }
}

/// Pay token allows a customer to make a payment; it is tied to a specific State and merchant
///
/// (via [`CustomerParameters`](crate::parameters::CustomerParameters::merchant_signing_pk)).
#[derive(Debug, Clone)]
pub struct PayToken(Signature);

/// Blinded signature on a [`PayToken`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedPayToken(/*BlindedSignature*/);

/// Blinding factor for a [`PayTokenCommitment`] and corresponding [`BlindedPayToken`]
#[derive(Debug, Clone, Copy)]
pub struct PayTokenBlindingFactor(BlindingFactor);

/// Commitment to a [`PayToken`], used to validate a [`BlindedPayToken`]
///
/// Note: this is a commitment to the message in the form for a _signature_ proof
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayTokenCommitment;

impl BlindedPayToken {
    /// Produces a [`BlindedPayToken`] by blindly signing the `State` in the given commitment.
    ///
    /// This is typically called by the merchant.
    pub fn new(_rng: &mut impl Rng, _param: &MerchantParameters, _com: StateCommitment) -> Self {
        todo!();
    }

    /// Unblinds a [`BlindedPayToken`] to get an (unblinded) [`PayToken`].
    ///
    /// This is typically called by the customer.
    pub fn unblind<'a>(self, _bf: Current<'a, PayTokenBlindingFactor>) -> Current<'a, PayToken> {
        todo!();
    }
}

impl PayToken {
    /// Verifies a `PayToken` against its corresponding [`State`].
    pub fn verify(&self, _param: &CustomerParameters, _state: &State) -> Verification {
        todo!();
    }
}
