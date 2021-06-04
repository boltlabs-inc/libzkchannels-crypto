//! Cryptographic routines to establish a new merchant, establish customer channels, and
//! process payments.

use crate::{
    customer,
    nonce::Nonce,
    proofs::{EstablishProof, PayProof},
    revlock::*,
    states::*,
    types::*,
};
use zkchannels_crypto::{pedersen_commitments::PedersenParameters, ps_keys::KeyPair};

/// A merchant that is ready to establish channels and process payments.
///
/// Holds keys and parameters used throughout the lifetime of a merchant node, across
/// all its channels.
#[derive(Debug)]
pub struct Config {
    /// KeyPair for signing, blind signing, and proofs.
    pub(crate) signing_keypair: KeyPair,
    pub(crate) revocation_parameters: PedersenParameters<G1Projective>,
}

impl Config {
    /// Instantiate a new merchant with all parameters.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        let signing_keypair = KeyPair::new(5, &mut rng);
        let revocation_parameters = PedersenParameters::new(1, &mut rng);

        Self {
            signing_keypair,
            revocation_parameters,
        }
    }

    /// Extract public configuration for customers.
    pub fn to_customer_config(&self) -> customer::Config {
        customer::Config {
            merchant_public_key: self.signing_keypair.public_key().clone(),
            revocation_parameters: self.revocation_parameters.clone(),
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
        _channel_id: &ChannelId,
        _customer_balance: CustomerBalance,
        _merchant_balance: MerchantBalance,
        _state_commitment: &StateCommitment,
        _close_state_commitment: CloseStateCommitment,
        _proof: EstablishProof,
    ) -> Option<crate::ClosingSignature> {
        todo!();
    }

    /**
    Activate a channel with the given ID.

    This should only be called if the [`ChannelId`] is stored in the merchant database with
    this [`StateCommitment`].
    */
    pub fn activate(
        &self,
        _channel_id: &ChannelId,
        _state_commitment: &StateCommitment,
    ) -> crate::PayToken {
        todo!();
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
        _nonce: &Nonce,
        _pay_proof: PayProof,
        _revocation_commitment: RevocationLockCommitment,
        _state_commitment: StateCommitment,
        _close_state_commitment: CloseStateCommitment,
    ) -> Option<(Unrevoked<'a>, crate::ClosingSignature)> {
        todo!();
    }
}
/**
A merchant that has approved a new payment on a channel, but has not received revocation
information for the previous channel state.
*/
#[derive(Debug)]
pub struct Unrevoked<'a> {
    config: &'a Config,
    revocation_commitment: RevocationLockCommitment,
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
        _revocation_lock: &RevocationLock,
        _revocation_secret: &RevocationSecret,
        _revocation_blinding_factor: &RevocationLockBlindingFactor,
    ) -> Result<crate::PayToken, Unrevoked<'a>> {
        todo!();
    }
}
