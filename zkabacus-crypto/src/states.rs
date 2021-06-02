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

use crate::{
    customer, merchant, revlock::*, types::*, Nonce, PaymentAmount, Rng, Verification, CLOSE_SCALAR,
};
use serde::*;
use zkchannels_crypto::{
    message::{BlindingFactor, Message},
    ps_blind_signatures::*,
    ps_signatures::{Signature, Verifier},
};

/// Channel identifier, binds each payment to a specific channel.
#[derive(Debug, Clone, Copy)]
pub struct ChannelId;

impl ChannelId {
    fn to_scalar(self) -> Scalar {
        todo!()
    }
}

/// Channel balance for merchant.
#[derive(Debug, Clone, Copy)]
pub struct MerchantBalance;

impl MerchantBalance {
    fn apply(self, _amt: PaymentAmount) -> Self {
        todo!()
    }

    fn to_scalar(self) -> Scalar {
        todo!()
    }
}

/// Channel balance for customer.
#[derive(Debug, Clone, Copy)]
pub struct CustomerBalance;

impl CustomerBalance {
    fn apply(self, _amt: PaymentAmount) -> Self {
        todo!()
    }

    fn to_scalar(self) -> Scalar {
        todo!()
    }
}

/// Describes the complete state of the channel with the given ID.
#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub(crate) struct State {
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
pub(crate) struct CloseState<'a> {
    channel_id: &'a ChannelId,
    revocation_lock: RevocationLock,
    merchant_balance: &'a MerchantBalance,
    customer_balance: &'a CustomerBalance,
}

#[allow(unused)]
impl State {
    /// Generate a new `State` with the given balances and ID.
    pub fn new(
        rng: &mut impl Rng,
        channel_id: ChannelId,
        merchant_balance: MerchantBalance,
        customer_balance: CustomerBalance,
    ) -> Self {
        Self {
            channel_id,
            nonce: Nonce::new(rng),
            revocation_secret: RevocationSecret::new(rng),
            merchant_balance,
            customer_balance,
        }
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
    pub(crate) fn revocation_lock(&self) -> RevocationLock {
        self.revocation_secret.revocation_lock()
    }

    /// Get the current [`Nonce`] for this state.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Get the revocation secret for this state.
    ///
    /// Once the revocation secret is removed and shared, the State is useless, so this function consumes it.
    pub fn revocation_secret(self) -> RevocationSecret {
        self.revocation_secret
    }

    /// Form a commitment (and corresponding blinding factor) to the `State`'s
    /// [`RevocationLock`].
    pub fn commit_to_revocation(
        &self,
        rng: &mut impl Rng,
        param: &customer::Config,
    ) -> (RevocationLockCommitment, RevocationLockBlindingFactor) {
        let blinding_factor = RevocationLockBlindingFactor::new(rng);
        let commitment = self.revocation_lock().commit(param, &blinding_factor);
        (commitment, blinding_factor)
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

    /// Apply a payment to the state by updating the balances appropriately and generating a new
    /// [`Nonce`] and [`RevocationLock`].
    ///
    /// A positive payment amount *decreases* the [`CustomerBalance`] and *increases* the
    /// [`MerchantBalance`]; a negative payment amount *increases* to the [`CustomerBalance`] and
    /// *decreases* the [`MerchantBalance`].
    ///
    /// This is typically called by the customer.
    pub fn apply_payment(&self, rng: &mut impl Rng, amt: PaymentAmount) -> State {
        State {
            channel_id: self.channel_id,
            nonce: Nonce::new(rng),
            revocation_secret: RevocationSecret::new(rng),
            customer_balance: self.customer_balance.apply(amt),
            merchant_balance: self.merchant_balance.apply(amt),
        }
    }

    /// Form a commitment (and corresponding blinding factor) to the [`State`] - that is, to the
    /// tuple (channel_id, nonce, revocation_lock, customer_balance, merchant_balance).
    ///
    /// Note that this _does not_ include the revocation secret!
    ///
    /// This is typically called by the customer.
    pub fn commit<'a>(
        &'a self,
        rng: &mut impl Rng,
        param: &customer::Config,
    ) -> (StateCommitment, PayTokenBlindingFactor) {
        let msg = self.to_message();
        let blinding_factor = BlindingFactor::new(rng);
        let commitment = param
            .merchant_public_key
            .blind_message(&msg, blinding_factor)
            .expect("mismatched message length.");

        (
            StateCommitment(commitment),
            PayTokenBlindingFactor(blinding_factor),
        )
    }

    /// Get the message representation of a State.
    fn to_message(&self) -> Message {
        Message::from(vec![
            self.channel_id.to_scalar(),
            self.nonce.to_scalar(),
            self.revocation_secret.revocation_lock().to_scalar(),
            self.customer_balance.to_scalar(),
            self.merchant_balance.to_scalar(),
        ])
    }
}

#[allow(unused)]
impl CloseState<'_> {
    /// Form a commitment (and corresponding blinding factor) to the [`CloseState`] and a constant,
    /// fixed close tag.
    ///
    /// This is typically called by the customer.
    pub fn commit<'a>(
        &'a self,
        rng: &mut impl Rng,
        param: &customer::Config,
    ) -> (CloseStateCommitment, CloseStateBlindingFactor) {
        let msg = self.to_message();
        let blinding_factor = BlindingFactor::new(rng);
        let commitment = param
            .merchant_public_key
            .blind_message(&msg, blinding_factor)
            .expect("mismatched lengths");

        (
            CloseStateCommitment(commitment),
            CloseStateBlindingFactor(blinding_factor),
        )
    }

    /// Get the message representation of a CloseState.
    fn to_message(&self) -> Message {
        Message::from(vec![
            self.channel_id.to_scalar(),
            CLOSE_SCALAR,
            self.revocation_lock.to_scalar(),
            self.customer_balance.to_scalar(),
            self.merchant_balance.to_scalar(),
        ])
    }
}

/// Commitment to a State: (channel_id, nonce, revocation_lock, customer_balance, merchant_balance).
///
/// Note that there is no direct verification function on `StateCommitment`s. They are
/// used to generate [`BlindedPayToken`]s.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct StateCommitment(BlindedMessage);

/// Commitment to a CloseState and a constant, fixed close tag.
///
/// Note that there is no direct verification function on `CloseStateCommitment`s. They are
/// used to generate [`CloseStateBlindedSignature`]s.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateCommitment(BlindedMessage);

/// Signature on a [`CloseState`] and a constant, fixed close tag. Used to close a channel.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub(crate) struct CloseStateSignature(Signature);

/// Blinded signature on a close state and a constant, fixed close tag.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateBlindedSignature(BlindedSignature);

/// Blinding factor for a [`CloseStateCommitment`] and corresponding [`CloseStateBlindedSignature`].
#[derive(Debug, Clone, Copy)]
#[allow(missing_copy_implementations)]
pub(crate) struct CloseStateBlindingFactor(BlindingFactor);

#[allow(unused)]
impl CloseStateBlindedSignature {
    /// Produce a [`CloseStateBlindedSignature`] by blindly signing the given [`CloseStateCommitment`].
    ///
    /// This is typically called by the merchant.
    pub(crate) fn new(
        rng: &mut impl Rng,
        param: &merchant::Config,
        com: CloseStateCommitment,
    ) -> CloseStateBlindedSignature {
        CloseStateBlindedSignature(param.signing_keypair.blind_sign(rng, &com.0))
    }

    /// Unblind a [`CloseStateBlindedSignature`] to get an (unblinded) [`CloseStateSignature`]
    /// using the given [`CloseStateBlindingFactor`].
    ///
    /// This is typically called by the customer.
    pub(crate) fn unblind(self, bf: CloseStateBlindingFactor) -> CloseStateSignature {
        CloseStateSignature(self.0.unblind(bf.0))
    }
}

#[allow(unused)]
impl CloseStateSignature {
    /// Verify the merchant signature against the given [`CloseState`].
    ///
    /// This is typically called by the customer.
    pub(crate) fn verify(
        &self,
        param: &customer::Config,
        close_state: CloseState<'_>,
    ) -> Verification {
        param
            .merchant_public_key
            .verify(&close_state.to_message(), &self.0)
            .into()
    }

    /// Randomize the `CloseStateSignature` in place.
    pub(crate) fn randomize(&mut self, rng: &mut impl Rng) {
        self.0.randomize(rng);
    }
}

/// A `PayToken` allows a customer to initiate a new payment. It is tied to a specific channel
/// [`State`].
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub(crate) struct PayToken(Signature);

/// A blinded pay token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedPayToken(BlindedSignature);

/// Blinding factor for a [`StateCommitment`] and corresponding [`BlindedPayToken`]
#[derive(Debug, Clone, Copy)]
pub(crate) struct PayTokenBlindingFactor(BlindingFactor);

#[allow(unused)]
impl BlindedPayToken {
    /// Produce a [`BlindedPayToken`] by blindly signing the given [`StateCommitment`].
    ///
    /// This is typically called by the merchant.
    pub(crate) fn new(rng: &mut impl Rng, param: &merchant::Config, com: &StateCommitment) -> Self {
        BlindedPayToken(param.signing_keypair.blind_sign(rng, &com.0))
    }

    /// Unblind a [`BlindedPayToken`] to get an (unblinded) [`PayToken`].
    ///
    /// This is typically called by the customer.
    pub(crate) fn unblind(self, bf: PayTokenBlindingFactor) -> PayToken {
        PayToken(self.0.unblind(bf.0))
    }
}

#[allow(unused)]
impl PayToken {
    /// Verify a `PayToken` against the given [`State`].
    ///
    /// This is typically called by the customer.
    pub fn verify(&self, param: &customer::Config, state: &State) -> Verification {
        param
            .merchant_public_key
            .verify(&state.to_message(), &self.0)
            .into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn apply_payment_works() {
        let mut rng = rand::thread_rng();
        let s = State::new(&mut rng, ChannelId, MerchantBalance, CustomerBalance);
        let _s_prev = s.apply_payment(&mut rng, PaymentAmount::pay_merchant(1));
    }
}
