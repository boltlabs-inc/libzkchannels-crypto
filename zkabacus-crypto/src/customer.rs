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

use crate::{
    nonce::Nonce,
    proofs::{BlindingFactors, EstablishProof, PayProof},
    revlock::*,
    states::*,
    types::*,
    PaymentAmount, Rng,
    Verification::{Failed, Verified},
};
use zkchannels_crypto::{pedersen_commitments::PedersenParameters, ps_keys::PublicKey};

/// Keys and parameters used throughout the lifetime of a channel.
#[derive(Debug)]
pub struct Config {
    /// Merchant public parameters for blind signing and proofs.
    pub(crate) merchant_public_key: PublicKey<5>,
    /// Pedersen parameters for committing to revocation locks.
    pub(crate) revocation_commitment_parameters: PedersenParameters<G1Projective, 1>,
}

impl Config {
    /// Construct a new customer configuration from the merchant's public parameters.
    pub fn new(
        merchant_public_key: PublicKey<5>,
        revocation_commitment_parameters: PedersenParameters<G1Projective, 1>,
    ) -> Self {
        Self {
            merchant_public_key,
            revocation_commitment_parameters,
        }
    }

    /// The merchant public key for blind signing and proofs.
    pub fn merchant_public_key(&self) -> &PublicKey<5> {
        &self.merchant_public_key
    }

    /// The parameters for committing to revocation locks.
    pub fn revocation_commitment_parameters(&self) -> &PedersenParameters<G1Projective, 1> {
        &self.revocation_commitment_parameters
    }
}

/// An activated channel that allows payments and closing.
/// This is a channel that has completed zkAbacus.Activate.
#[derive(Debug)]
pub struct Ready {
    config: Config,
    state: State,
    pay_token: PayToken,
    close_state_signature: CloseStateSignature,
}

/// A channel that has been requested but not yet approved.
/// This is an intermediary state of zkAbacus.Initialize.
#[derive(Debug)]
pub struct Requested {
    config: Config,
    state: State,
    close_state_blinding_factor: CloseStateBlindingFactor,
    pay_token_blinding_factor: PayTokenBlindingFactor,
}

/// Message sent to the merchant to request a new channel.
/// This is sent as part of zkAbacus.Initialize.
#[derive(Debug)]
#[non_exhaustive]
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
    This is part of zkAbacus.Initialize.
    */
    pub fn new(
        rng: &mut impl Rng,
        config: Config,
        channel_id: ChannelId,
        merchant_balance: MerchantBalance,
        customer_balance: CustomerBalance,
    ) -> (Self, RequestMessage) {
        // Construct initial state.
        let state = State::new(rng, channel_id, merchant_balance, customer_balance);
        let close_state = state.close_state();

        // Commit to state and corresponding close state.
        let (state_commitment, pay_token_blinding_factor) = state.commit(rng, &config);
        let (close_state_commitment, close_state_blinding_factor) =
            close_state.commit(rng, &config);

        // Form proof that the state / close state are correct.
        let proof = EstablishProof::new(
            rng,
            &config,
            &state,
            close_state_blinding_factor,
            pay_token_blinding_factor,
        );

        (
            Self {
                config,
                state,
                close_state_blinding_factor,
                pay_token_blinding_factor,
            },
            RequestMessage {
                close_state_commitment,
                state_commitment,
                proof,
            },
        )
    }

    /// Complete channel initiation: validate approval received from the merchant.
    /// This is part of zkAbacus.Initialize.
    pub fn complete(
        self,
        closing_signature: crate::ClosingSignature,
    ) -> Result<Inactive, Requested> {
        // Unblind close signature and verify it is correct.
        let close_state_signature = closing_signature.unblind(self.close_state_blinding_factor);
        match close_state_signature.verify(&self.config, self.state.close_state()) {
            // If so, save it and enter the `Inactive` state.
            Verified => Ok(Inactive {
                config: self.config,
                state: self.state,
                blinding_factor: self.pay_token_blinding_factor,
                close_state_signature,
            }),
            Failed => Err(self),
        }
    }
}

/// A channel that has been approved but not yet activated.
/// This is a channel that has completed zkAbacus.Initialize.
#[derive(Debug)]
pub struct Inactive {
    config: Config,
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Inactive {
    /// Activate the channel with the fresh pay token from the merchant.
    /// This is part of zkAbacus.Activate.
    pub fn activate(self, pay_token: crate::PayToken) -> Result<Ready, Inactive> {
        // Unblind pay token signature (on the state) and verify it is correct.
        let unblinded_pay_token = pay_token.unblind(self.blinding_factor);
        match unblinded_pay_token.verify(&self.config, &self.state) {
            // If so, save it and enter the `Ready` state.
            Verified => Ok(Ready {
                config: self.config,
                state: self.state,
                pay_token: unblinded_pay_token,
                close_state_signature: self.close_state_signature,
            }),
            Failed => Err(self),
        }
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
    /// The commitment to the (not yet revealed) revocation lock.
    pub revocation_lock_commitment: RevocationLockCommitment,
    /// The commitment to the close state.
    pub close_state_commitment: CloseStateCommitment,
    /// The commitment to the state.
    pub state_commitment: StateCommitment,
}

impl Ready {
    /// Start a payment of the given [`PaymentAmount`].
    /// This is part of zkAbacus.Pay.
    pub fn start(self, rng: &mut impl Rng, amount: PaymentAmount) -> (Started, StartMessage) {
        // Generate correctly-updated state.
        let new_state = self.state.apply_payment(rng, amount);

        // Commit to new state and old revocation lock.
        let (revocation_lock_commitment, revocation_lock_bf) =
            self.state.commit_to_revocation(rng, &self.config);
        let (state_commitment, state_bf) = self.state.commit(rng, &self.config);
        let (close_state_commitment, close_state_bf) =
            self.state.close_state().commit(rng, &self.config);

        // Save the blinding factors together.
        let blinding_factors = BlindingFactors {
            for_revocation_lock: revocation_lock_bf,
            for_pay_token: state_bf,
            for_close_state: close_state_bf,
        };

        // Form proof that the payment correctly updates a valid state.
        let pay_proof = PayProof::new(
            rng,
            &self.config,
            self.pay_token,
            &self.state,
            &new_state,
            blinding_factors,
        );

        let old_nonce = *self.state.nonce();
        (
            Started {
                config: self.config,
                new_state,
                old_state: self.state,
                blinding_factors,
                old_close_state_signature: self.close_state_signature,
            },
            StartMessage {
                nonce: old_nonce,
                pay_proof,
                revocation_lock_commitment,
                close_state_commitment,
                state_commitment,
            },
        )
    }

    /// Extract data used to close the channel.
    pub fn close(self) -> Closing {
        todo!()
    }
}

/// A channel that has started a new payment.
/// This is the first intermediary state in zkAbacus.Pay.
#[derive(Debug)]
pub struct Started {
    config: Config,
    new_state: State,
    old_state: State,
    blinding_factors: BlindingFactors,
    old_close_state_signature: CloseStateSignature,
}

/// Message sent to the merchant to revoke the old balance and lock the channel.
/// This is sent as part of zkAbacus.Pay.
#[derive(Debug)]
#[non_exhaustive]
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
    /// This is part of zkAbacus.Pay.
    pub fn lock(
        self,
        closing_signature: crate::ClosingSignature,
    ) -> Result<(Locked, LockMessage), Started> {
        // Unblind close signature and verify it is correct.
        let close_state_signature =
            closing_signature.unblind(self.blinding_factors.for_close_state);
        match close_state_signature.verify(&self.config, self.new_state.close_state()) {
            // If so, save it, reveal the revocation information for the old close signature and
            // enter the `Locked` state.
            Verified => Ok((
                Locked {
                    config: self.config,
                    state: self.new_state,
                    blinding_factor: self.blinding_factors.for_pay_token,
                    close_state_signature,
                },
                LockMessage {
                    revocation_lock: self.old_state.revocation_lock(),
                    revocation_secret: self.old_state.revocation_secret(),
                    revocation_lock_blinding_factor: self.blinding_factors.for_revocation_lock,
                },
            )),
            Failed => Err(self),
        }
    }

    /// Extract data used to close the channel on the previous balances.
    pub fn close(self) -> Closing {
        todo!()
    }
}

/// A channel that has made a payment but not yet been given permission by the merchant to make
/// another payment.
/// This is the second intermediary state of zkAbacus.Pay.
#[derive(Debug)]
pub struct Locked {
    config: Config,
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Locked {
    /// Unlock the channel by validating the merchant's approval message.
    /// This is the final step of zkAbacus.Pay.
    pub fn unlock(self, pay_token: crate::PayToken) -> Result<Ready, Locked> {
        // Unblind pay token signature (on the state) and verify it is correct.
        let unblinded_pay_token = pay_token.unblind(self.blinding_factor);
        match unblinded_pay_token.verify(&self.config, &self.state) {
            // If so, save it and enter the `Ready` state.
            Verified => Ok(Ready {
                config: self.config,
                state: self.state,
                pay_token: unblinded_pay_token,
                close_state_signature: self.close_state_signature,
            }),
            Failed => Err(self),
        }
    }

    /// Extract data used to close the channel.
    pub fn close(self) -> Closing {
        todo!()
    }
}
