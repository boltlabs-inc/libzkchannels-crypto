//! Cryptographic routines to establish a new merchant, establish customer channels, and
//! process payments.
//! A merchant is essentially a stateless object, so nearly all these functions are atomic API calls on
//! the merchant configuration [`Config`].
//!
//! **Important:** Most of these API calls have a documented **Usage** requirement: typically, the
//! merchant must ensure that certain parameters are *fresh*, and have never been seen before.
//! These checks *must* be made for a correct zkAbacus execution.
//!
//! ## Init
//! A merchant initializes itself by creating parameters that will be used over its entire lifetime.
//!
//! ## Establish
//! This is a two-phase process. First, the merchant must [`initialize()`](Config::initialize())
//! a given channel id, which verifies that the customer has correctly set up the channel state.
//! Once initialized, it must [`activate()`](Config::activate()) the
//! channel to allow the customer to begin making payments.
//!
//! ## Pay
//! This is also a two-phase process, with an intermediate state. First, the merchant receives a
//! payment request and decides whether to [`allow_payment()`](Config::allow_payment()), making sure the
//! request is well-formed and valid. If so, it enters the [`Unrevoked`] state, indicating that
//! the customer has not yet revoked the previous channel state. At this point, the customer cannot
//! make another payment. Once the customer revokes the previous state, the
//! merchant can [`complete_payment()](Unrevoked::complete_payment()) and allow the customer to make
//! new payments once again.
//!
//! ## Close
//! The merchant can process a close request from the customer with
//! [`check_close_signature`](Config::check_close_signature()).
//!
//!
//!
//!
//!
//!
//!

use crate::{
    customer,
    nonce::Nonce,
    proofs::{Context, EstablishProof, EstablishProofPublicValues, PayProof, PayProofPublicValues},
    revlock::*,
    states::*,
    types::*,
    PaymentAmount, Rng,
    Verification::{self, Failed, Verified},
};
use zkchannels_crypto::{
    pedersen::PedersenParameters, pointcheval_sanders::KeyPair, proofs::RangeProofParameters,
};

/// A merchant that is ready to establish channels and process payments.
/// This is a merchant that has completed zkAbacus.Init.
///
/// Holds keys and parameters used throughout the lifetime of a merchant node, across
/// all its channels.
#[derive(Debug, Eq, PartialEq)]
#[allow(missing_copy_implementations)]
pub struct Config {
    /// KeyPair for signing, blind signing, and proofs.
    pub(crate) signing_keypair: KeyPair<5>,
    /// Pedersen parameters for committing to revocation locks.
    pub(crate) revocation_commitment_parameters: PedersenParameters<G1Projective, 1>,
    /// Parameters for generating and verifying range proofs.
    pub(crate) range_proof_parameters: RangeProofParameters,
}

impl Config {
    /// Instantiate a new merchant with all parameters.
    /// This is called as part of zkAbacus.Init.
    pub fn new(rng: &mut impl Rng) -> Self {
        Self {
            signing_keypair: KeyPair::new(rng),
            revocation_commitment_parameters: PedersenParameters::new(rng),
            range_proof_parameters: RangeProofParameters::new(rng),
        }
    }

    /// Instantiate a merchant with pre-defined parameters.
    pub fn from_parts(
        signing_keypair: crate::KeyPair,
        revocation_commitment_parameters: crate::CommitmentParameters,
        range_proof_parameters: RangeProofParameters,
    ) -> Self {
        Self {
            signing_keypair,
            revocation_commitment_parameters,
            range_proof_parameters,
        }
    }

    /// Extract public configuration for customers.
    pub(crate) fn to_customer_config(&self) -> customer::Config {
        customer::Config {
            merchant_public_key: self.signing_keypair.public_key().clone(),
            revocation_commitment_parameters: self.revocation_commitment_parameters.clone(),
            range_proof_parameters: self.range_proof_parameters.clone(),
        }
    }

    /// Extract public configuration for customers.
    #[allow(unused_qualifications)]
    pub fn extract_customer_config_parts(
        &self,
    ) -> (
        crate::PublicKey,
        crate::CommitmentParameters,
        crate::RangeProofParameters,
    ) {
        (
            self.signing_keypair.public_key().clone(),
            self.revocation_commitment_parameters.clone(),
            self.range_proof_parameters.clone(),
        )
    }

    /// Extract Pointcheval-Sanders [`KeyPair`].
    pub fn signing_keypair(&self) -> &crate::KeyPair {
        &self.signing_keypair
    }

    /// Extract [`PedersenParameters`] for commitments to revocation locks.
    pub fn revocation_commitment_parameters(&self) -> &crate::CommitmentParameters {
        &self.revocation_commitment_parameters
    }

    /// Extract [`RangeProofParameters`].
    pub fn range_proof_parameters(&self) -> &RangeProofParameters {
        &self.range_proof_parameters
    }

    /**
    Respond to a customer request to initialize a new channel.
    This is called as part of zkAbacus.Initialize.

    Fails in the case where the given [`EstablishProof`] does not verify with respect to the
    public variables (channel ID, balances, and provided commitments).

    **Usage**: The given `channel_id` *must* be fresh; this should only be called if the [`ChannelId`]
    has never been seen before.

    Note: there are two "flavors" of inputs here. Channel ID + balances are public inputs, should
    be agreed on outside of zkAbacus. The commitments + proof are received from the customer.
    */
    pub fn initialize(
        &self,
        rng: &mut impl Rng,
        channel_id: &ChannelId,
        customer_balance: CustomerBalance,
        merchant_balance: MerchantBalance,
        proof: EstablishProof,
        context: &Context,
    ) -> Option<(crate::ClosingSignature, StateCommitment)> {
        // Collect items used to verify the proof.
        let public_values = EstablishProofPublicValues {
            channel_id: *channel_id,
            merchant_balance,
            customer_balance,
        };
        // Verify that proof is consistent with the expected inputs.
        match proof.verify(&self, &public_values, context) {
            // If so, blindly sign the close state.
            Verified => {
                let (state_commitment, close_state_commitment) = proof.extract_commitments();
                Some((
                    CloseStateBlindedSignature::sign(rng, &self, close_state_commitment),
                    state_commitment,
                ))
            }
            Failed => None,
        }
    }

    /**
    Activate a channel with the given ID. This is called as part of zkAbacus.Activate.

    **Usage**: The [`StateCommitment`] *must* be associated with a valid [`EstablishProof`]. This
    should only be called _after_ the merchant has successfully run [`initialize()`](Config::initialize())
    with the given `state_commitment`.
    */
    pub fn activate(
        &self,
        rng: &mut impl Rng,
        state_commitment: StateCommitment,
    ) -> crate::PayToken {
        // Blindly sign the pay token.
        // Note that this should _only_ be called after the merchant has received a valid
        // `EstablishProof` that is consistent with the `state_commitment`.
        BlindedPayToken::sign(rng, &self, &state_commitment)
    }

    /**
    On receiving a payment request, issue a [`ClosingSignature`](crate::ClosingSignature) on the
    updated state, if the provided evidence is valid.
    This is called as part of zkAbacus.Pay.

    **Usage**: The given [`Nonce`] *must* be fresh; this should only be called if the `nonce` has
    never been seen before.

    This will fail if the [`PayProof`] is not verifiable with the provided commitments and
    [`Nonce`].
    */
    pub fn allow_payment<'a>(
        &'a self,
        rng: &mut impl Rng,
        amount: PaymentAmount,
        nonce: &Nonce,
        pay_proof: PayProof,
        context: &Context,
    ) -> Option<(Unrevoked<'a>, crate::ClosingSignature)> {
        // Collect items used to verify the proof.
        let public_values = PayProofPublicValues {
            old_nonce: *nonce,
            amount,
        };
        // Verify that proof is consistent with the expected inputs.
        match pay_proof.verify(&self, &public_values, context) {
            // If so, blindly sign the close state.
            Verified => {
                let (revocation_lock_commitment, state_commitment, close_state_commitment) =
                    pay_proof.extract_commitments();
                Some((
                    Unrevoked {
                        config: &self,
                        revocation_lock_commitment,
                        state_commitment,
                    },
                    CloseStateBlindedSignature::sign(rng, &self, close_state_commitment),
                ))
            }
            Failed => None,
        }
    }

    /// Validate closing information: make sure the [`CloseStateSignature`] is on the given
    /// [`CloseState`]. This is called as part of zkAbacus.Close.
    ///
    /// **Usage**: The [`CloseState`] *must* be fresh; this should only be run if the revocation
    /// lock in the given `close_state` has never been seen before.
    pub fn check_close_signature(
        &self,
        close_signature: CloseStateSignature,
        close_state: CloseState,
    ) -> Verification {
        // Verify the signature is on the message
        close_signature.verify(&self.to_customer_config(), close_state)
    }
}
/**
A merchant that has approved a new payment on a channel, but has not received revocation
information for the previous channel state.

This is an intermediary state in zkAbacus.Pay.
*/
#[derive(Debug)]
pub struct Unrevoked<'a> {
    config: &'a Config,
    revocation_lock_commitment: RevocationLockCommitment,
    state_commitment: StateCommitment,
}

impl<'a> Unrevoked<'a> {
    /**
    Complete a payment by issuing a pay token on the updated state, if the revocation information
    is well-formed.
    This is called as part of zkAbacus.Pay.

    **Usage**: This should *only* be called if the revocation lock has never been seen before.

    This will fail if the revocation information is not well-formed (e.g. the revocation lock does
    not match the revocation secret; or it does not match the stored revocation commitment).
    */
    pub fn complete_payment(
        self,
        rng: &mut impl Rng,
        revocation_lock: &RevocationLock,
        revocation_secret: &RevocationSecret,
        revocation_blinding_factor: &RevocationLockBlindingFactor,
    ) -> Result<crate::PayToken, Unrevoked<'a>> {
        // Verify that the provided parameters are consistent and they match the stored commitment.
        match self.revocation_lock_commitment.verify(
            self.config,
            revocation_secret,
            revocation_lock,
            revocation_blinding_factor,
        ) {
            // If so, blindly sign the pay token.
            // Note that the merchant should _only_ call this function after receiving
            // a valid [`PayProof`] that is consistent with the given `state_commitment`.
            Verified => Ok(BlindedPayToken::sign(
                rng,
                self.config,
                &self.state_commitment,
            )),
            Failed => Err(self),
        }
    }
}
