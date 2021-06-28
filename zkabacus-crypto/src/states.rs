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
    customer, merchant, revlock::*, types::*, Balance, Error, Nonce, PaymentAmount, Rng,
    Verification, CLOSE_SCALAR,
};
use serde::*;
use sha3::{Digest, Sha3_256};
use std::convert::{TryFrom, TryInto};
use zkchannels_crypto::{pointcheval_sanders::*, BlindingFactor, Message};

/// Randomness produced by the customer, used to create the [`ChannelId`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CustomerRandomness([u8; 32]);

impl CustomerRandomness {
    /// Generates `CustomerRandomness` uniformly at random.
    pub fn new(rng: &mut impl Rng) -> Self {
        let mut buf = [0; 32];
        rng.fill_bytes(&mut buf);
        Self(buf)
    }
}

/// Randomness produced by the merchant, used to create the [`ChannelId`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MerchantRandomness([u8; 32]);

impl MerchantRandomness {
    /// Generates `MerchantRandomness` uniformly at random.
    pub fn new(rng: &mut impl Rng) -> Self {
        let mut buf = [0; 32];
        rng.fill_bytes(&mut buf);
        Self(buf)
    }
}

/// Channel identifier, binds each payment to a specific channel.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChannelId([u8; 32]);

#[cfg(feature = "sqlite")]
impl_sqlx_for_bincode_ty!(ChannelId);

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        base64::encode(self.0).fmt(f)
    }
}

impl ChannelId {
    /// Generate a new channel ID from randomness and public key information.
    pub fn new(
        merchant_randomness: MerchantRandomness,
        customer_randomness: CustomerRandomness,
        public_key: &PublicKey<5>,
        merchant_account_info: &[u8],
        customer_account_info: &[u8],
    ) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(&merchant_randomness.0);
        hasher.update(&customer_randomness.0);
        hasher.update(public_key.to_bytes());
        hasher.update(merchant_account_info);
        hasher.update(customer_account_info);
        let bytes = hasher.finalize().try_into().unwrap();
        Self(bytes)
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&self.0[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&self.0[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&self.0[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&self.0[24..32]).unwrap()),
        ])
    }
}

/// Channel balance for merchant.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MerchantBalance(Balance);

impl MerchantBalance {
    /// Create a new merchant balance.
    ///
    /// Raise an error if the proposed balance is too large.
    pub fn try_new(value: u64) -> Result<Self, Error> {
        Balance::try_new(value).map(Self)
    }

    fn apply(self, amt: PaymentAmount) -> Result<Self, Error> {
        // The merchant adds, the customer subtracts
        let new_value = self.0 .0 as i128 + amt.0 as i128;
        if new_value.is_negative() {
            Err(Error::InsufficientFunds)
        } else {
            Self::try_new(new_value as u64)
        }
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        self.0.to_scalar()
    }

    /// Convert into the inner `u64` value. Per internal invariants, this will always produce a
    /// `u64` which is less than `i64::MAX`.
    pub fn into_inner(self) -> u64 {
        self.0.into_inner()
    }
}

/// Channel balance for customer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CustomerBalance(Balance);

impl CustomerBalance {
    /// Create a new customer balance.
    ///
    /// Raise an error if the proposed balance is too large.
    pub fn try_new(value: u64) -> Result<Self, Error> {
        Balance::try_new(value).map(Self)
    }

    fn apply(self, amt: PaymentAmount) -> Result<Self, Error> {
        // The merchant adds, the customer subtracts
        let new_value = self.0 .0 as i128 - amt.0 as i128;
        if new_value.is_negative() {
            Err(Error::InsufficientFunds)
        } else {
            Self::try_new(new_value as u64)
        }
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        self.0.to_scalar()
    }

    /// Convert into the inner `u64` value. Per internal invariants, this will always produce a
    /// `u64` which is less than `i64::MAX`.
    pub fn into_inner(self) -> u64 {
        self.0.into_inner()
    }
}

/// Describes the complete state of the channel with the given ID.
#[allow(missing_copy_implementations)]
#[derive(Debug, Serialize, Deserialize)]
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
/// It removes the nonce from the associated `State` to maintain privacy during closing, even in the case of
/// merchant abort during payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseState {
    channel_id: ChannelId,
    revocation_lock: RevocationLock,
    merchant_balance: MerchantBalance,
    customer_balance: CustomerBalance,
}

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
    pub fn close_state(&self) -> CloseState {
        let State {
            channel_id,
            merchant_balance,
            customer_balance,
            ..
        } = self;
        CloseState {
            channel_id: *channel_id,
            revocation_lock: self.revocation_lock(),
            merchant_balance: *merchant_balance,
            customer_balance: *customer_balance,
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
    pub fn apply_payment(&self, rng: &mut impl Rng, amt: PaymentAmount) -> Result<State, Error> {
        Ok(State {
            channel_id: self.channel_id,
            nonce: Nonce::new(rng),
            revocation_secret: RevocationSecret::new(rng),
            customer_balance: self.customer_balance.apply(amt)?,
            merchant_balance: self.merchant_balance.apply(amt)?,
        })
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
            .blind_message(&msg, blinding_factor);

        (
            StateCommitment(commitment),
            PayTokenBlindingFactor(blinding_factor),
        )
    }

    /// Get the message representation of a State.
    pub(crate) fn to_message(&self) -> Message<5> {
        Message::new([
            self.channel_id.to_scalar(),
            self.nonce.as_scalar(),
            self.revocation_secret.revocation_lock().to_scalar(),
            self.customer_balance.to_scalar(),
            self.merchant_balance.to_scalar(),
        ])
    }
}

impl CloseState {
    /// Form a commitment (and corresponding blinding factor) to the [`CloseState`] and a constant,
    /// fixed close tag.
    ///
    /// This is typically called by the customer.
    pub(crate) fn commit<'a>(
        &'a self,
        rng: &mut impl Rng,
        param: &customer::Config,
    ) -> (CloseStateCommitment, CloseStateBlindingFactor) {
        let msg = self.to_message();
        let blinding_factor = BlindingFactor::new(rng);
        let commitment = param
            .merchant_public_key
            .blind_message(&msg, blinding_factor);

        (
            CloseStateCommitment(commitment),
            CloseStateBlindingFactor(blinding_factor),
        )
    }

    /// Get the message representation of a CloseState.
    pub(crate) fn to_message(&self) -> Message<5> {
        Message::new([
            self.channel_id.to_scalar(),
            CLOSE_SCALAR,
            self.revocation_lock.to_scalar(),
            self.customer_balance.to_scalar(),
            self.merchant_balance.to_scalar(),
        ])
    }

    /// Get the [`ChannelId`] for this [`CloseState`].
    pub fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    /// Get the revocation lock for the [`CloseState`].
    pub fn revocation_lock(&self) -> &RevocationLock {
        &self.revocation_lock
    }

    /// Get the merchant's current [`MerchantBalance`] for this [`CloseState`].
    pub fn merchant_balance(&self) -> &MerchantBalance {
        &self.merchant_balance
    }

    /// Get the customer's current [`CustomerBalance`] for this [`CloseState`].
    pub fn customer_balance(&self) -> &CustomerBalance {
        &self.customer_balance
    }
}

/// Commitment to a State: (channel_id, nonce, revocation_lock, customer_balance, merchant_balance).
///
/// Note that there is no direct verification function on `StateCommitment`s. They are
/// used to generate [`BlindedPayToken`]s.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct StateCommitment(pub(crate) BlindedMessage);

/// Commitment to a CloseState and a constant, fixed close tag.
///
/// Note that there is no direct verification function on `CloseStateCommitment`s. They are
/// used to generate [`CloseStateBlindedSignature`]s.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateCommitment(pub(crate) BlindedMessage);

/// Signature on a [`CloseState`] and a constant, fixed close tag. Used to close a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateSignature(pub(crate) Signature);

/// Blinded signature on a close state and a constant, fixed close tag.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct CloseStateBlindedSignature(pub(crate) BlindedSignature);

/// Blinding factor for a [`CloseStateCommitment`] and corresponding [`CloseStateBlindedSignature`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct CloseStateBlindingFactor(pub(crate) BlindingFactor);

impl CloseStateBlindedSignature {
    /// Produce a [`CloseStateBlindedSignature`] by blindly signing the given [`CloseStateCommitment`].
    ///
    /// This is typically called by the merchant.
    pub(crate) fn sign(
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

impl CloseStateSignature {
    /// Verify the merchant signature against the given [`CloseState`].
    ///
    /// This is typically called by the customer.
    pub(crate) fn verify(
        &self,
        param: &customer::Config,
        close_state: &CloseState,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct PayToken(pub(crate) Signature);

/// A blinded pay token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedPayToken(BlindedSignature);

/// Blinding factor for a [`StateCommitment`] and corresponding [`BlindedPayToken`]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayTokenBlindingFactor(pub(crate) BlindingFactor);

impl BlindedPayToken {
    /// Produce a [`BlindedPayToken`] by blindly signing the given [`StateCommitment`].
    ///
    /// This is typically called by the merchant.
    pub(crate) fn sign(
        rng: &mut impl Rng,
        param: &merchant::Config,
        com: &StateCommitment,
    ) -> Self {
        BlindedPayToken(param.signing_keypair.blind_sign(rng, &com.0))
    }

    /// Unblind a [`BlindedPayToken`] to get an (unblinded) [`PayToken`].
    ///
    /// This is typically called by the customer.
    pub(crate) fn unblind(self, bf: PayTokenBlindingFactor) -> PayToken {
        PayToken(self.0.unblind(bf.0))
    }
}

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

    fn channel_id(rng: &mut impl Rng) -> ChannelId {
        let cid_m = MerchantRandomness::new(rng);
        let cid_c = CustomerRandomness::new(rng);
        let pk = KeyPair::new(rng).public_key().clone();
        ChannelId::new(cid_m, cid_c, &pk, &[], &[])
    }

    #[test]
    fn apply_positive_payment_works() {
        let mut rng = rand::thread_rng();
        let channel_id = channel_id(&mut rng);
        let s = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(0).unwrap(),
            CustomerBalance::try_new(1).unwrap(),
        );

        let _s_prev = s.apply_payment(&mut rng, PaymentAmount::pay_merchant(1).unwrap());
        let s_prime = s
            .apply_payment(&mut rng, PaymentAmount::pay_merchant(1).unwrap())
            .unwrap();

        assert_eq!(s_prime.merchant_balance.0 .0, 1);
        assert_eq!(s_prime.customer_balance.0 .0, 0);
    }

    #[test]
    fn apply_negative_payment_works() {
        let mut rng = rand::thread_rng();
        let channel_id = channel_id(&mut rng);
        let s = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(1).unwrap(),
            CustomerBalance::try_new(0).unwrap(),
        );
        let s_prime = s
            .apply_payment(&mut rng, PaymentAmount::pay_customer(1).unwrap())
            .unwrap();

        assert_eq!(s_prime.merchant_balance.0 .0, 0);
        assert_eq!(s_prime.customer_balance.0 .0, 1);
    }

    #[test]
    #[should_panic = "InsufficientFunds"]
    fn apply_payment_fails_for_insufficient_customer_funds() {
        let mut rng = rand::thread_rng();
        let channel_id = channel_id(&mut rng);
        let s = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(0).unwrap(),
            CustomerBalance::try_new(1).unwrap(),
        );
        let _ = s
            .apply_payment(&mut rng, PaymentAmount::pay_merchant(2).unwrap())
            .unwrap();
    }

    #[test]
    #[should_panic = "InsufficientFunds"]
    fn apply_payment_fails_for_insufficient_merchant_funds() {
        let mut rng = rand::thread_rng();
        let channel_id = channel_id(&mut rng);
        let s = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(0).unwrap(),
            CustomerBalance::try_new(1).unwrap(),
        );
        let _ = s
            .apply_payment(&mut rng, PaymentAmount::pay_customer(1).unwrap())
            .unwrap();
    }
}
