/*!
Cryptographic routines for establishing, making payments on, and closing a zkAbacus channel.

## Establish

Channel establishment for the customer has two phases. First, the customer _initializes_ the
channel. They form a [`RequestMessage`] that proves they have correctly formed the channel
state with respect to the agreed-upon balances and enter the [`Requested`]
state.

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
[`Closing`] information.
*/

use crate::nonce::Nonce;
use crate::proofs::EstablishProof;
use crate::proofs::*;
use crate::revlock::*;
use crate::states::*;
use crate::PaymentAmount;

/// Keys and parameters used throughout the lifetime of a channel.
#[derive(Debug, Clone, Copy)]
pub struct Config {}

/// An activated channel that allows payments and closing.
#[derive(Debug)]
pub struct Ready {
    config: Config,
    state: State,
    pay_token: PayToken,
    close_state_signature: CloseStateSignature,
}

/// A channel that has been requested but not yet approved.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct Requested {
    config: Config,
    channel_id: ChannelId,
    merchant_balance: MerchantBalance,
    customer_balance: CustomerBalance,
    state: State,
    close_state_blinding_factor: CloseStateBlindingFactor,
    pay_token_blinding_factor: PayTokenBlindingFactor,
}

/// Message sent to the merchant to request a new channel.
#[derive(Debug)]
pub struct RequestMessage {
    /// Commitment to the initial close state.
    pub close_state_commitment: CloseStateCommitment,
    /// Commitment to the initial state.
    pub state_commitment: StateCommitment,
    /// Proof that channel is being correctly established.
    pub proof: EstablishProof,
}

impl Requested {
    /**
    Generate a new channel request from public parameters.

    FIXME(Marcella). The API doesn't yet determine how `Config` is generated. It may be better
    to pass the components here, rather than the generated object.
    */
    pub fn new(
        _config: Config,
        _channel_id: ChannelId,
        _merchant_balance: MerchantBalance,
        _customer_balance: CustomerBalance,
    ) -> (Self, RequestMessage) {
        todo!();
    }

    /// Complete channel initiation: validate approval received from the merchant.
    pub fn complete(
        self,
        _closing_signature: crate::ClosingSignature,
    ) -> Result<Inactive, Requested> {
        todo!();
    }
}

/// A channel that has been approved but not yet activated.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct Inactive {
    config: Config,
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Inactive {
    /// Activate the channel with the fresh pay token from the merchant.
    pub fn activate(self, _pay_token: crate::PayToken) -> Result<Ready, Inactive> {
        todo!();
    }
}
/// Message sent to the merchant after starting a payment.
#[derive(Debug)]
pub struct StartMessage {
    /// The current customer state's random nonce.
    pub nonce: Nonce,
    /// The zero-knowledge proof of the validity of the payment.
    pub pay_proof: PayProof,
    /// The commitment to the (not yet revealed) revocation lock.
    pub revocation_lock_commitment: RevocationLockCommitment,
    /// The commitment to the close state.
    pub close_state_commitment: CloseStateCommitment,
    /// The commitment to the state.
    pub state_commitment: StateCommitment,
}

impl Ready {
    /// Start a payment of the given [`PaymentAmount`].
    pub fn start(self, _amount: PaymentAmount) -> (Started, StartMessage) {
        todo!()
    }

    /// Extract data used to close the channel.
    pub fn close(self) -> Closing {
        todo!()
    }
}

/// A channel that has started a new payment.
#[derive(Debug)]
pub struct Started {
    config: Config,
    new_state: State,
    old_state: State,
    blinding_factors: BlindingFactors,
    old_close_state_signature: CloseStateSignature,
}

/// Message sent to the merchant to revoke the old balance and lock the channel.
#[derive(Debug)]
pub struct LockMessage {
    /// Revocation lock
    pub revocation_lock: RevocationLock,
    /// Revocation secret
    pub revocation_secret: RevocationSecret,
    /// Blinding factor for commitment to revocation lock
    pub revocation_lock_blinding_factor: RevocationLockBlindingFactor,
}

/// The information necessary to perform a close for a state.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct Closing {}

impl Started {
    /// Revoke the ability to close the channel on the outdated balances.
    pub fn lock(
        self,
        _closing_signature: crate::ClosingSignature,
    ) -> Result<(Locked, LockMessage), Started> {
        todo!();
    }

    /// Extract data used to close the channel on the previous balances.
    pub fn close(self) -> Closing {
        todo!()
    }
}

/// A channel that has made a payment but not yet been given permission by the merchant to make
/// another payment.
#[derive(Debug)]
pub struct Locked {
    config: Config,
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Locked {
    /// Unlock the channel by validating the merchant's approval message.
    pub fn unlock(self, _pay_token: crate::PayToken) -> Result<Ready, Locked> {
        todo!()
    }

    /// Extract data used to close the channel.
    pub fn close(self) -> Closing {
        todo!()
    }
}
