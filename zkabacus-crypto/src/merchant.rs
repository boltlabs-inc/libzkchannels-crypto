//! Cryptographic routines to establish a new merchant, establish customer channels, and
//! process payments.

use crate::{
    customer,
    nonce::Nonce,
    proofs::{EstablishProof, EstablishProofVerification, PayProof, PayProofVerification},
    revlock::*,
    states::*,
    types::*,
    PaymentAmount,
    Verification::{Failed, Verified},
};
use zkchannels_crypto::{pedersen_commitments::PedersenParameters, ps_keys::KeyPair};

/// A merchant that is ready to establish channels and process payments.
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
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let signing_keypair = KeyPair::new(5, &mut rng);
        let revocation_commitment_parameters = PedersenParameters::new(1, &mut rng);

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

    Fails in the case where the given [`EstablishProof`] does not verify with respect to the
    public variables (channel ID, balances, and provided commitments).

    The given `channel_id` *must* be fresh; this should only be called if the [`ChannelId`] has
    never been seen before.

    Note: there are two "flavors" of inputs here. Channel ID + balances are public inputs, should
    be agreed on outside of zkAbacus. The commitments + proof are received from the customer.
    */
    pub fn initialize(
        &self,
        channel_id: &ChannelId,
        customer_balance: CustomerBalance,
        merchant_balance: MerchantBalance,
        state_commitment: &StateCommitment,
        close_state_commitment: CloseStateCommitment,
        proof: EstablishProof,
    ) -> Option<crate::ClosingSignature> {
        let verification_objects = EstablishProofVerification {
            state_commitment,
            close_state_commitment,
            channel_id: *channel_id,
            merchant_balance,
            customer_balance,
        };

        let mut rng = rand::thread_rng();
        match proof.verify(&self, &verification_objects) {
            Verified => Some(CloseStateBlindedSignature::new(
                &mut rng,
                &self,
                verification_objects.close_state_commitment,
            )),
            Failed => None,
        }
    }

    /**
    Activate a channel with the given ID.

    This should only be called if the [`StateCommitment`] is stored in the merchant database with
    a known [`ChannelId`].
    */
    pub fn activate(&self, state_commitment: &StateCommitment) -> crate::PayToken {
        let mut rng = rand::thread_rng();
        BlindedPayToken::new(&mut rng, &self, state_commitment)
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
        amount: PaymentAmount,
        nonce: &Nonce,
        pay_proof: PayProof,
        revocation_lock_commitment: RevocationLockCommitment,
        state_commitment: StateCommitment,
        close_state_commitment: CloseStateCommitment,
    ) -> Option<(Unrevoked<'a>, crate::ClosingSignature)> {
        let verification_objects = PayProofVerification {
            revocation_lock_commitment: &revocation_lock_commitment,
            state_commitment: &state_commitment,
            close_state_commitment: &close_state_commitment,
            nonce: *nonce,
            amount,
        };
        let mut rng = rand::thread_rng();
        match pay_proof.verify(&self, &verification_objects) {
            Verified => Some((
                Unrevoked {
                    config: &self,
                    revocation_lock_commitment,
                    state_commitment,
                },
                CloseStateBlindedSignature::new(&mut rng, &self, close_state_commitment),
            )),
            Failed => None,
        }
    }
}
/**
A merchant that has approved a new payment on a channel, but has not received revocation
information for the previous channel state.
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

    This should only be called if the revocation lock has never been seen before.

    This will fail if the revocation information is not well-formed (e.g. the revocation lock does
    not match the revocation secret; or it does not match the stored revocation commitment).
    */
    pub fn complete_payment(
        self,
        revocation_lock: &RevocationLock,
        revocation_secret: &RevocationSecret,
        revocation_blinding_factor: &RevocationLockBlindingFactor,
    ) -> Result<crate::PayToken, Unrevoked<'a>> {
        let mut rng = rand::thread_rng();
        // Verify that the provided parameters are consistent and they match the stored commitment.
        match self.revocation_lock_commitment.verify(
            self.config,
            revocation_secret,
            revocation_lock,
            revocation_blinding_factor,
        ) {
            Verified => Ok(BlindedPayToken::new(
                &mut rng,
                self.config,
                &self.state_commitment,
            )),
            Failed => Err(self),
        }
    }
}
