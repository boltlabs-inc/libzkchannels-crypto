/*!
Cryptographic routines for establishing, making payments on, and closing a zkAbacus channel.

## Establish

Channel establishment for the customer has two phases. First, the customer _initializes_ the
channel. They form an [`EstablishProof`] that proves they have correctly formed the channel
state with respect to the agreed-upon balances and enter the [`Requested`] state.

On receiving a valid [`ClosingSignature`](crate::ClosingSignature), they
[`complete()`](Requested::complete()) the initialize phase and enter the [`Inactive`] state.

In the second phase, the customer _activates_ the channel. On receiving a valid
[`PayToken`](crate::PayToken), they enter the [`Ready`] state.

## Pay

Payments on a channel have three phases. The customer begins in the [`Ready`] state.

First, the customer begins the payment protocol. Using an agreed-upon amount, they
[`start()`](Ready::start()) the payment and enter the [`Started`] state.
This produces a [`StartMessage`], which proves that they have correctly updated the
channel state with respect to the payment amount.

On receiving a [`ClosingSignature`](crate::ClosingSignature), the customer can
[`lock()`](Started::lock()) the channel and enter the [`Locked`] state.
This produces a [`LockMessage`], which revokes the old channel state;
at this point, the customer _cannot_ make another payment.

On receiving a [`PayToken`](crate::PayToken), the payment is complete and the customer returns to
the [`Ready`] state.

## Close

The customer has the option to close at multiple points in the protocol:

- [`Inactive`]. A channel that hasn't been activated can still close on the original balances.
- [`Ready`]. An activated channel can close on the current balances.
- [`Started`]. After a payment has been started, the customer can close on the previous balances.
- [`Locked`]. A locked channel can close on the updated balances.

At any of these points, the customer can call the associated `close()` function to retrieve the
[`ClosingMessage`] information.
*/

use crate::{
    nonce::Nonce,
    proofs::{BlindingFactors, Context, EstablishProof, PayProof},
    revlock::*,
    states::*,
    types::*,
    Error, PaymentAmount, Rng,
    Verification::{Failed, Verified},
};
use serde::*;
use zkchannels_crypto::{
    pedersen::PedersenParameters, pointcheval_sanders::PublicKey, proofs::RangeConstraintParameters,
};

/// Keys and parameters used throughout the lifetime of a channel.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Config {
    /// Merchant public parameters for blind signing and proofs.
    pub(crate) merchant_public_key: PublicKey<5>,
    /// Pedersen parameters for committing to revocation locks.
    pub(crate) revocation_commitment_parameters: PedersenParameters<G1Projective, 1>,
    /// Parameters for building and verifying range constraints.
    pub(crate) range_constraint_parameters: RangeConstraintParameters,
}

#[cfg(feature = "sqlite")]
impl_sqlx_for_bincode_ty!(Config);

impl Config {
    /// Construct a new customer configuration from the merchant's public parameters.
    pub fn from_parts(
        merchant_public_key: PublicKey<5>,
        revocation_commitment_parameters: PedersenParameters<G1Projective, 1>,
        range_constraint_parameters: RangeConstraintParameters,
    ) -> Self {
        Self {
            merchant_public_key,
            revocation_commitment_parameters,
            range_constraint_parameters,
        }
    }

    /// The merchant public key for blind signing and proofs.
    pub fn merchant_public_key(&self) -> &crate::PublicKey {
        &self.merchant_public_key
    }

    /// The parameters for committing to revocation locks.
    pub fn revocation_commitment_parameters(&self) -> &crate::CommitmentParameters {
        &self.revocation_commitment_parameters
    }

    /// The parameters for constructing range constraints.
    pub fn range_constraint_parameters(&self) -> &RangeConstraintParameters {
        &self.range_constraint_parameters
    }
}

/// An activated channel that allows payments and closing.
/// This is a channel that has completed zkAbacus.Activate.
#[derive(Debug, Serialize, Deserialize)]
pub struct Ready {
    state: State,
    pay_token: PayToken,
    close_state_signature: CloseStateSignature,
}

/// A channel that has been requested but not yet approved.
/// This is an intermediary state of zkAbacus.Initialize.
#[derive(Debug, Serialize, Deserialize)]
pub struct Requested {
    state: State,
    close_state_blinding_factor: CloseStateBlindingFactor,
    pay_token_blinding_factor: PayTokenBlindingFactor,
}

impl Requested {
    /**
    Generate a new channel request from public parameters.
    This is called as part of zkAbacus.Initialize.
    */
    pub fn new(
        rng: &mut impl Rng,
        config: &Config,
        channel_id: ChannelId,
        merchant_balance: MerchantBalance,
        customer_balance: CustomerBalance,
        context: &Context,
    ) -> (Self, EstablishProof) {
        // Construct initial state.
        let state = State::new(rng, channel_id, merchant_balance, customer_balance);

        // Form proof that the state / close state are correct.
        let (proof, close_state_blinding_factor, pay_token_blinding_factor) =
            EstablishProof::new(rng, config, &state, context);

        (
            Self {
                state,
                close_state_blinding_factor,
                pay_token_blinding_factor,
            },
            proof,
        )
    }

    /// Complete channel initiation: validate approval received from the merchant.
    /// This is called as part of zkAbacus.Initialize.
    pub fn complete(
        self,
        closing_signature: crate::ClosingSignature,
        config: &Config,
    ) -> Result<Inactive, Requested> {
        // Unblind close signature and verify it is correct.
        let close_state_signature = closing_signature.unblind(self.close_state_blinding_factor);
        match close_state_signature.verify(config, &self.state.close_state()) {
            // If so, save it and enter the `Inactive` state.
            Verified => Ok(Inactive {
                state: self.state,
                blinding_factor: self.pay_token_blinding_factor,
                close_state_signature,
            }),
            Failed => Err(self),
        }
    }

    /// Get the current [`CustomerBalance`] for this state.
    ///
    /// This represents the proposed customer contribution to the yet-to-be-established channel.
    pub fn customer_balance(&self) -> CustomerBalance {
        self.state.customer_balance()
    }

    /// Get the current [`MerchantBalance`] for this state.
    ///
    /// This represents the proposed merchant contribution to the yet-to-be-established channel.
    pub fn merchant_balance(&self) -> MerchantBalance {
        self.state.merchant_balance()
    }

    /// Get the [`ChannelId`] for this state.
    pub fn channel_id(&self) -> &ChannelId {
        self.state.channel_id()
    }
}

/// A channel that has been approved but not yet activated.
/// This is a channel that has completed zkAbacus.Initialize.
#[derive(Debug, Serialize, Deserialize)]
pub struct Inactive {
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Inactive {
    /// Activate the channel with the fresh pay token from the merchant.
    /// This is called as part of zkAbacus.Activate.
    pub fn activate(self, pay_token: crate::PayToken, config: &Config) -> Result<Ready, Inactive> {
        // Unblind pay token signature (on the state) and verify it is correct.
        let unblinded_pay_token = pay_token.unblind(self.blinding_factor);
        match unblinded_pay_token.verify(config, &self.state) {
            // If so, save it and enter the `Ready` state.
            Verified => Ok(Ready {
                state: self.state,
                pay_token: unblinded_pay_token,
                close_state_signature: self.close_state_signature,
            }),
            Failed => Err(self),
        }
    }

    /// Extract data used to close the channel.
    /// This is called as part of zkAbacus.Close.
    pub fn close(self, rng: &mut impl Rng) -> ClosingMessage {
        ClosingMessage::new(rng, self.close_state_signature, self.state.close_state())
    }

    /// Get the current [`CustomerBalance`] for this state.
    ///
    /// This represents the customer contribution to the yet-to-be-activated channel.
    pub fn customer_balance(&self) -> CustomerBalance {
        self.state.customer_balance()
    }

    /// Get the current [`MerchantBalance`] for this state.
    ///
    /// This represents the merchant contribution to the yet-to-be-activated channel.
    pub fn merchant_balance(&self) -> MerchantBalance {
        self.state.merchant_balance()
    }

    /// Get the [`ChannelId`] for this state.
    pub fn channel_id(&self) -> &ChannelId {
        self.state.channel_id()
    }
}

/// Message sent to the merchant after starting a payment.
/// This is sent as part of zkAbacus.Pay.
#[derive(Debug)]
#[non_exhaustive]
pub struct StartMessage {
    /// The current customer state's random nonce.
    pub nonce: Nonce,
    /// The zero-knowledge proof of the validity of the payment.
    pub pay_proof: PayProof,
}

impl Ready {
    /// Start a payment of the given [`PaymentAmount`].
    /// This is part of zkAbacus.Pay.
    pub fn start(
        self,
        rng: &mut impl Rng,
        amount: PaymentAmount,
        context: &Context,
        config: &Config,
    ) -> Result<(Started, StartMessage), (Ready, Error)> {
        // Generate correctly-updated state.
        let new_state = match self.state.apply_payment(rng, amount) {
            Ok(new_state) => new_state,
            Err(error) => return Err((self, error)),
        };

        // Form proof that the payment correctly updates a valid state.
        let (pay_proof, blinding_factors) = PayProof::new(
            rng,
            config,
            self.pay_token,
            &self.state,
            &new_state,
            context,
        );

        // Save nonce.
        let old_nonce = *self.state.nonce();

        Ok((
            Started {
                new_state,
                old_state: self.state,
                blinding_factors,
                old_close_state_signature: self.close_state_signature,
            },
            StartMessage {
                nonce: old_nonce,
                pay_proof,
            },
        ))
    }

    /// Extract data used to close the channel.
    /// This is called as part of zkAbacus.Close.
    pub fn close(self, rng: &mut impl Rng) -> ClosingMessage {
        ClosingMessage::new(rng, self.close_state_signature, self.state.close_state())
    }

    /// Get the current [`CustomerBalance`] for this state, prior to starting a payment.
    pub fn customer_balance(&self) -> CustomerBalance {
        self.state.customer_balance()
    }

    /// Get the current [`MerchantBalance`] for this state, prior to starting a payment.
    pub fn merchant_balance(&self) -> MerchantBalance {
        self.state.merchant_balance()
    }

    /// Get the [`ChannelId`] for this state.
    pub fn channel_id(&self) -> &ChannelId {
        self.state.channel_id()
    }
}

/// A channel that has started a new payment.
/// This is the first intermediary state in zkAbacus.Pay.
#[derive(Debug, Serialize, Deserialize)]
pub struct Started {
    new_state: State,
    old_state: State,
    blinding_factors: BlindingFactors,
    old_close_state_signature: CloseStateSignature,
}

/// Message sent to the merchant to revoke the old balance and lock the channel.
/// This is sent as part of zkAbacus.Pay.
///
/// This type does not derive `Clone` because the revocation information in the `LockMessage`
/// is unique and should only be sent to a merchant once.
#[derive(Debug)]
#[non_exhaustive]
pub struct LockMessage {
    /// Revocation pair
    pub revocation_pair: RevocationPair,
    /// Blinding factor for commitment to revocation lock
    pub revocation_lock_blinding_factor: RevocationLockBlindingFactor,
}

/// The information necessary to perform a close for a state.
/// This is sent as part of zkAbacus.Close.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClosingMessage {
    close_signature: CloseStateSignature,
    close_state: CloseState,
}

impl ClosingMessage {
    /// Create a new `ClosingMessage`. This randomizes the signature.
    pub fn new(
        rng: &mut impl Rng,
        mut close_signature: CloseStateSignature,
        close_state: CloseState,
    ) -> Self {
        close_signature.randomize(&mut *rng);
        Self {
            close_signature,
            close_state,
        }
    }

    /// Get the closing [`CustomerBalance`] for this [`ClosingMessage`].
    pub fn customer_balance(&self) -> CustomerBalance {
        self.close_state.customer_balance()
    }

    /// Get the closing [`MerchantBalance`] for this [`ClosingMessage`].
    pub fn merchant_balance(&self) -> MerchantBalance {
        self.close_state.merchant_balance()
    }

    /// Get the [`ChannelId`] for this [`ClosingMessage`].
    pub fn channel_id(&self) -> &ChannelId {
        self.close_state.channel_id()
    }

    /// Get a reference to the [`RevocationLock`] contained in this [`ClosingMessage`].
    pub fn revocation_lock(&self) -> &RevocationLock {
        self.close_state.revocation_lock()
    }

    /// Get a reference to the [`CloseStateSignature`] contained in this [`ClosingMessage`].
    pub fn closing_signature(&self) -> &CloseStateSignature {
        &self.close_signature
    }

    /// Consume and decompose a `ClosingMessage` into its constituent parts.
    pub fn into_parts(self) -> (CloseStateSignature, CloseState) {
        (self.close_signature, self.close_state)
    }
}

impl Started {
    /// Revoke the ability to close the channel on the outdated balances.
    /// This is part of zkAbacus.Pay.
    pub fn lock(
        self,
        closing_signature: crate::ClosingSignature,
        config: &Config,
    ) -> Result<(Locked, LockMessage), Started> {
        // Unblind close signature and verify it is correct.
        let close_state_signature =
            closing_signature.unblind(self.blinding_factors.for_close_state);
        match close_state_signature.verify(config, &self.new_state.close_state()) {
            // If so, save it, reveal the revocation information for the old close signature and
            // enter the `Locked` state.
            Verified => Ok((
                Locked {
                    state: self.new_state,
                    blinding_factor: self.blinding_factors.for_pay_token,
                    close_state_signature,
                },
                LockMessage {
                    revocation_pair: self.old_state.revocation_pair(),
                    revocation_lock_blinding_factor: self.blinding_factors.for_old_revocation_lock,
                },
            )),
            Failed => Err(self),
        }
    }

    /// Extract data used to close the channel on the previous balances.
    /// This is called as part of zkAbacus.Close.
    pub fn close(self, rng: &mut impl Rng) -> ClosingMessage {
        ClosingMessage::new(
            rng,
            self.old_close_state_signature,
            self.old_state.close_state(),
        )
    }

    /// Get the [`CustomerBalance`] for this state prior to the current payment in progress.
    ///
    /// Note that although the payment has been started, this is the *old* balance, because this is
    /// what would be closed on if the [`Started::close`] method was called from this state.
    pub fn customer_balance(&self) -> CustomerBalance {
        self.old_state.customer_balance()
    }

    /// Get the [`MerchantBalance`] for this state prior to the current payment in progress.
    ///
    /// Note that although the payment has been started, this is the *old* balance, because this is
    /// what would be closed on if the [`Started::close`] method was called from this state.
    pub fn merchant_balance(&self) -> MerchantBalance {
        self.old_state.merchant_balance()
    }

    /// Get the [`ChannelId`] for this state.
    pub fn channel_id(&self) -> &ChannelId {
        self.old_state.channel_id()
    }
}

/// A channel that has made a payment but not yet been given permission by the merchant to make
/// another payment.
///
/// This is the second intermediary state of zkAbacus.Pay.
#[derive(Debug, Serialize, Deserialize)]
pub struct Locked {
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Locked {
    /// Unlock the channel by validating the merchant's approval message.
    /// This is the final step of zkAbacus.Pay.
    pub fn unlock(self, pay_token: crate::PayToken, config: &Config) -> Result<Ready, Locked> {
        // Unblind pay token signature (on the state) and verify it is correct.
        let unblinded_pay_token = pay_token.unblind(self.blinding_factor);
        match unblinded_pay_token.verify(config, &self.state) {
            // If so, save it and enter the `Ready` state.
            Verified => Ok(Ready {
                state: self.state,
                pay_token: unblinded_pay_token,
                close_state_signature: self.close_state_signature,
            }),
            Failed => Err(self),
        }
    }

    /// Extract data used to close the channel.
    /// This is called as part of zkAbacus.Close.
    pub fn close(self, rng: &mut impl Rng) -> ClosingMessage {
        ClosingMessage::new(rng, self.close_state_signature, self.state.close_state())
    }

    /// Get the [`CustomerBalance`] for this state that will result from completing the payment in
    /// progress or closing the channel.
    ///
    /// Note that although the payment has not yet been completed, this is the *new* balance,
    /// because this is what would be closed on if the [`Locked::close`] method was called from this
    /// state.
    pub fn customer_balance(&self) -> CustomerBalance {
        self.state.customer_balance()
    }

    /// Get the [`MerchantBalance`] for this state that will result from completing the payment in
    /// progress or closing the channel.
    ///
    /// Note that although the payment has not yet been completed, this is the *new* balance,
    /// because this is what would be closed on if the [`Locked::close`] method was called from this
    /// state.
    pub fn merchant_balance(&self) -> MerchantBalance {
        self.state.merchant_balance()
    }

    /// Get the [`ChannelId`] for this state.
    pub fn channel_id(&self) -> &ChannelId {
        self.state.channel_id()
    }
}
