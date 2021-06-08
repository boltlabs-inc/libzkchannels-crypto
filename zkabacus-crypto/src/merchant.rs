//! Cryptographic routines to establish a new merchant, establish customer channels, and
//! process payments.

use crate::{
    customer,
    nonce::Nonce,
    proofs::{EstablishProof, EstablishProofVerification, PayProof, PayProofVerification},
    revlock::*,
    states::*,
    types::*,
    PaymentAmount, Rng,
    Verification::{Failed, Verified},
};
use zkchannels_crypto::{pedersen_commitments::PedersenParameters, ps_keys::KeyPair};

/// A merchant that is ready to establish channels and process payments.
/// This is a merchant that has completed zkAbacus.Init.
///
/// Holds keys and parameters used throughout the lifetime of a merchant node, across
/// all its channels.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct Config {
    /// KeyPair for signing, blind signing, and proofs.
    pub(crate) signing_keypair: KeyPair,
    /// Pedersen parameters for committing to revocation locks.
    pub(crate) revocation_commitment_parameters: PedersenParameters<G1Projective>,
}

impl Config {
    /// Instantiate a new merchant with all parameters.
    /// This executes zkAbacus.Init.
    #[allow(clippy::new_without_default)]
    pub fn new(rng: &mut impl Rng) -> Self {
        let signing_keypair = KeyPair::new(5, rng);
        let revocation_commitment_parameters = PedersenParameters::new(1, rng);

        Self {
            signing_keypair,
            revocation_commitment_parameters,
        }
    }

    /// Extract public configuration for customers.
    pub fn to_customer_config(&self) -> customer::Config {
        customer::Config {
            merchant_public_key: self.signing_keypair.public_key().clone(),
            revocation_commitment_parameters: self.revocation_commitment_parameters.clone(),
        }
    }

    /**
    Respond to a customer request to initialize a new channel.
    This executes zkAbacus.Initialize.

    Fails in the case where the given [`EstablishProof`] does not verify with respect to the
    public variables (channel ID, balances, and provided commitments).

    The given `channel_id` *must* be fresh; this should only be called if the [`ChannelId`] has
    never been seen before.

    Note: there are two "flavors" of inputs here. Channel ID + balances are public inputs, should
    be agreed on outside of zkAbacus. The commitments + proof are received from the customer.
    */
    pub fn initialize(
        &self,
        rng: &mut impl Rng,
        channel_id: &ChannelId,
        customer_balance: CustomerBalance,
        merchant_balance: MerchantBalance,
        state_commitment: &StateCommitment,
        close_state_commitment: CloseStateCommitment,
        proof: EstablishProof,
    ) -> Option<crate::ClosingSignature> {
        // Collect items used to verify the proof.
        let verification_objects = EstablishProofVerification {
            state_commitment,
            close_state_commitment,
            channel_id: *channel_id,
            merchant_balance,
            customer_balance,
        };
        // Verify that proof is consistent with the expected inputs.
        match proof.verify(&self, &verification_objects) {
            // If so, blindly sign the close state.
            Verified => Some(CloseStateBlindedSignature::new(
                rng,
                &self,
                verification_objects.close_state_commitment,
            )),
            Failed => None,
        }
    }

    /**
    Activate a channel with the given ID. This is part of zkAbacus.Activate.

    This should only be called _after_ the merchant has executed [`initialize()`](Config::initialize()) for the given
    [`ChannelId`].
    */
    pub fn activate(
        &self,
        rng: &mut impl Rng,
        state_commitment: &StateCommitment,
    ) -> crate::PayToken {
        // Blindly sign the pay token.
        // Note that this should _only_ be called after the merchant has received a valid
        // `EstablishProof` that is consistent with the `state_commitment`.
        BlindedPayToken::new(rng, &self, state_commitment)
    }

    /**
    On receiving a payment request, issue a [`ClosingSignature`](crate::ClosingSignature) on the
    updated state, if the provided evidence is valid.
    This is part of zkAbacus.Pay.

    This should only be called if the [`Nonce`] has never been seen before.

    This will fail if the [`PayProof`] is not verifiable with the provided commitments and
    [`Nonce`].
    */
    pub fn allow_payment<'a>(
        &'a self,
        rng: &mut impl Rng,
        amount: PaymentAmount,
        nonce: &Nonce,
        pay_proof: PayProof,
        revocation_lock_commitment: RevocationLockCommitment,
        state_commitment: StateCommitment,
        close_state_commitment: CloseStateCommitment,
    ) -> Option<(Unrevoked<'a>, crate::ClosingSignature)> {
        // Collect items used to verify the proof.
        let verification_objects = PayProofVerification {
            revocation_lock_commitment: &revocation_lock_commitment,
            state_commitment: &state_commitment,
            close_state_commitment: &close_state_commitment,
            nonce: *nonce,
            amount,
        };
        // Verify that proof is consistent with the expected inputs.
        match pay_proof.verify(&self, &verification_objects) {
            // If so, blindly sign the close state.
            Verified => Some((
                Unrevoked {
                    config: &self,
                    revocation_lock_commitment,
                    state_commitment,
                },
                CloseStateBlindedSignature::new(rng, &self, close_state_commitment),
            )),
            Failed => None,
        }
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
    This is part of zkAbacus.Pay.

    This should only be called if the revocation lock has never been seen before.

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
            Verified => Ok(BlindedPayToken::new(
                rng,
                self.config,
                &self.state_commitment,
            )),
            Failed => Err(self),
        }
    }
}
