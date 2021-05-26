/*!
Defines the state of a channel and transformations on that state used in the zkAbacus
protocol.

The primary type is a [`State`], which describes a zkChannel at a point in time. The protocol
applies several transformations to this object to generate the customer outputs of the zkAbacus.Pay
subprotocol: a [`PayToken`] and a [`CloseStateSignature`]. For each of these outputs, the flow
goes as follows:

1. the customer blinds an input,
2. the merchant verifies (in zero knowledge) that the input is correctly formed,
3. the merchant produces a blinded version of the output, and
4. the customer unblinds the output.

To produce a [`PayToken`], the customer blinds the [`State`] with a [`PayTokenBlindingFactor`].
This produces a [`StateCommitment`], which the merchant signs to produce a [`BlindedPayToken`].

To produce a [`CloseStateSignature`], the customer blinds the [`CloseState`] with a
[`CloseStateBlindingFactor`]. This produces a [`CloseStateCommitment`], which the merchant signs
to produce a [`CloseStateBlindedSignature`].

The customer must blind the input and unblind the output with the _same_ blinding factor.
*/
use serde::*;

use crate::nonce::*;
use crate::revlock::*;
use crate::types::*;
use crate::PaymentAmount;
use crate::{customer, merchant};
use crate::{Rng, Verification};
use message::BlindingFactor;
use ps_signatures::Signature;

/// Channel identifier, binds each payment to a specific channel.
#[derive(Debug, Clone, Copy)]
pub struct ChannelId;

/// Channel balance for merchant.
#[derive(Debug, Clone, Copy)]
pub struct MerchantBalance;

/// Channel balance for customer.
#[derive(Debug, Clone, Copy)]
pub struct CustomerBalance;

/// Describes the complete state of the channel with the given ID.
#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct State {
    channel_id: ChannelId,
    nonce: Nonce,
    revocation_secret: RevocationSecret,
    merchant_balance: MerchantBalance,
    customer_balance: CustomerBalance,
}

/// The closing state associated with a state.
///
/// When signed by the merchant, this can be used by the customer to close the channel.
/// It removes the nonce from the [`State`] to maintain privacy during closing, even in the case of
/// merchant abort during payment.
#[derive(Debug)]
pub struct CloseState<'a> {
    channel_id: &'a ChannelId,
    revocation_lock: RevocationLock,
    merchant_balance: &'a MerchantBalance,
    customer_balance: &'a CustomerBalance,
}

impl State {
    /// Generate a new `State` with the given balances and ID.
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

    /// Get the customer's current [`CustomerBalance`] for this state.
    pub fn customer_balance(&self) -> &CustomerBalance {
        &self.customer_balance
    }

    /// Get the current [`RevocationLock`] for this state.
    pub fn revocation_lock(&self) -> RevocationLock {
        self.revocation_secret.revocation_lock()
    }

    /// Get the current [`Nonce`] for this state.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Get the revocation secret for this state.
    pub fn revocation_secret(&self) -> &RevocationSecret {
        &self.revocation_secret
    }

    /// Form a commitment (and corresponding blinding factor) to the `State`'s
    /// [`RevocationLock`].
    pub fn commit_to_revocation<'a>(
        &'a self,
        _rng: &mut impl Rng,
        _param: &customer::Config,
    ) -> (RevocationLockCommitment, RevocationLockBlindingFactor) {
        todo!();
    }

    /// Get the [`CloseState`] corresponding to this `State`.
    ///
    /// This is typically called by the customer.
    pub fn close_state(&self) -> CloseState<'_> {
        let State {
            channel_id,
            revocation_secret,
            merchant_balance,
            customer_balance,
            ..
        } = self;
        CloseState {
            channel_id,
            revocation_lock: revocation_secret.revocation_lock(),
            merchant_balance,
            customer_balance,
        }
    }

    /// Apply a payment to the state by updating the balances appropriately and generating new
    /// [`Nonce`] and [`RevocationLock`] (returning the corresponding [`RevocationSecret`]).
    ///
    /// A positive payment amount *deducts* from the [`CustomerBalance`] and *adds* to the
    /// [`MerchantBalance`]; a negative payment amount *adds* to the [`CustomerBalance`] and
    /// *deducts* from the [`MerchantBalance`].
    ///
    /// This is typically called by the customer.
    pub fn apply_payment<'a>(&'a mut self, _rng: &mut impl Rng, _amt: &PaymentAmount) -> State {
        todo!();
    }

    /// Form a commitment (and corresponding blinding factor) to the [`State`].
    ///
    /// This is typically called by the customer.
    pub fn commit<'a>(
        &'a self,
        _rng: &mut impl Rng,
        _param: &customer::Config,
    ) -> (StateCommitment, PayTokenBlindingFactor) {
        todo!();
    }
}

impl CloseState<'_> {
    /// Form a commitment (and corresponding blinding factor) to the [`CloseState`].
    ///
    /// This is typically called by the customer.
    pub fn commit<'a>(
        &'a self,
        _rng: &mut impl Rng,
        _param: &customer::Config,
    ) -> (CloseStateCommitment, CloseStateBlindingFactor) {
        todo!();
    }
}

/// Commitment to a State.
///
/// This satisfies the standard properties of a commitment scheme:
///
/// *Correctness*: A correctly-generated commitment will always verify.
///
/// *Hiding*: A `StateCommitment` does not reveal anything about the underlying [`State`].
///
/// *Binding*: Given a `StateCommitment`, an adversary cannot efficiently generate a
/// [`State`] and [`PayTokenBlindingFactor`] that verify with the commitment.
///
/// Note that there is no direct verification function on `StateCommitment`s. They are
/// used to generate [`BlindedPayToken`]s.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct StateCommitment(/*Commitment*/);

/// Commitment to a CloseState.
///
/// This satisfies the standard properties of a commitment scheme:
///
/// *Correctness*: A correctly-generated commitment will always verify.
///
/// *Hiding*: A `CloseStateCommitment` does not reveal anything about the underlying [`CloseState`].
///
/// *Binding*: Given a `CloseStateCommitment`, an adversary cannot efficiently generate a
/// [`CloseState`] and [`CloseStateBlindingFactor`] that verify with the commitment.
///
/// Note that there is no direct verification function on `CloseStateCommitment`s. They are
/// used to generate [`CloseStateBlindedSignature`]s.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateCommitment(/*Commitment*/);

/// Signature on a [`CloseState`]. Used to close a channel.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct CloseStateSignature;

/// Blinded signature on a [`CloseState`].
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateBlindedSignature;

/// Blinding factor for a [`CloseStateCommitment`] and corresponding [`CloseStateBlindedSignature`].
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct CloseStateBlindingFactor;

impl CloseStateBlindedSignature {
    /// Produce a [`CloseStateBlindedSignature`] by blindly signing the given [`CloseStateCommitment`].
    ///
    /// This is typically called by the merchant.
    pub fn new(
        _rng: &mut impl Rng,
        _param: &merchant::Config,
        _com: CloseStateCommitment,
    ) -> CloseStateBlindedSignature {
        todo!();
    }

    /// Unblind a [`CloseStateBlindedSignature`] to get an (unblinded) [`CloseStateSignature`]
    /// using the given [`CloseStateBlindingFactor`].
    ///
    /// This is typically called by the customer.
    pub fn unblind(self, _bf: CloseStateBlindingFactor) -> CloseStateSignature {
        todo!();
    }
}

impl CloseStateSignature {
    /// Verify the merchant signature against the given [`CloseState`].
    ///
    /// This is typically called by the customer.
    pub fn verify(&self, _param: &customer::Config, _close_state: CloseState<'_>) -> Verification {
        todo!();
    }
}

/// A `PayToken` allows a customer to initiate a new payment. It is tied to a specific channel
/// [`State`].
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct PayToken(Signature);

/// Blinded [`PayToken`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedPayToken(/*BlindedSignature*/);

/// Blinding factor for a [`StateCommitment`] and corresponding [`BlindedPayToken`]
#[derive(Debug, Clone, Copy)]
pub struct PayTokenBlindingFactor(BlindingFactor);

impl BlindedPayToken {
    /// Produce a [`BlindedPayToken`] by blindly signing the given [`StateCommitment`].
    ///
    /// This is typically called by the merchant.
    pub fn new(_rng: &mut impl Rng, _param: &merchant::Config, _com: StateCommitment) -> Self {
        todo!();
    }

    /// Unblind a [`BlindedPayToken`] to get an (unblinded) [`PayToken`].
    ///
    /// This is typically called by the customer.
    pub fn unblind(self, _bf: PayTokenBlindingFactor) -> PayToken {
        todo!();
    }
}

impl PayToken {
    /// Verify a `PayToken` against the given [`State`].
    ///
    /// This is typically called by the customer.
    pub fn verify(&self, _param: &customer::Config, _state: &State) -> Verification {
        todo!();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn apply_payment_works() {
        let mut rng = rand::thread_rng();
        let mut s = State::new(&mut rng, ChannelId, MerchantBalance, CustomerBalance);
        let _s_prev = s.apply_payment(&mut rng, &PaymentAmount::pay_merchant(1));
    }
}
