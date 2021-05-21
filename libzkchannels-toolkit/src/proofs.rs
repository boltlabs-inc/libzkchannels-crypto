/*!
This describes the zero-knowledge proofs used in the Establish and Pay subprotocols of
zkChannels.

These proofs are formed by the customer and demonstrate that they know the current state of the
channel and have modified it appropriately. The merchant verifies the proofs, confirming that
the customer is behaving correctly without learning any additional information about the channel state.
*/
use serde::*;

use crate::nonce::*;
use crate::revlock::*;
use crate::states::*;
use crate::{customer, merchant};
use crate::{Rng, Verification};

/**
An establish proof demonstrates that a customer is trying to initialize a channel correctly.

This is a Schnorr proof that makes the following guarantees in zero knowledge:

- The balances in the [`State`] match the previously-agreed-upon values.
- The underlying [`State`] and [`CloseState`] from the [`StateCommitment`] and
  [`CloseStateCommitment`] are correctly formed relative to each other.
*/
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EstablishProof;

impl EstablishProof {
    /**
    Form a new zero-knowledge [`EstablishProof`] object.

    It takes the [`State`] and two current blinding factors. These should correspond to
    commitments made from the given [`State`] and its associated [`CloseState`].

    This function is typically called by the customer.
    */
    pub fn new(
        _rng: &mut impl Rng,
        _params: &customer::Config,
        _state: &State,
        _close_state_blinding_factor: CloseStateBlindingFactor,
        _pay_token_blinding_factor: PayTokenBlindingFactor,
    ) -> Self {
        todo!();
    }

    /// Verify the [`EstablishProof`] against the provided verification objects.
    ///
    /// This function is typically called by the merchant.
    pub fn verify(
        &self,
        _params: &merchant::Config,
        _verification_objects: &EstablishProofVerification,
    ) -> Verification {
        todo!();
    }
}

/// Collects the information a merchant needs to verify a [`EstablishProof`].
#[derive(Debug)]
pub struct EstablishProofVerification {
    /// Commitment to a [`State`].
    pub state_commitment: StateCommitment,
    /// Commitment to a `CloseState`.
    pub close_state_commitment: CloseStateCommitment,
    /// Expected channel ID.
    pub channel_id: ChannelId,
    /// Expected merchant balance.
    pub merchant_balance: MerchantBalance,
    /// Expected customer balance.
    pub customer_balance: CustomerBalance,
}

/**
A payment proof demonstrates that a customer is trying to make a valid payment on a channel.

This is a Schnorr proof that makes the following guarantees in zero knowledge:

- The customer holds a valid [`PayToken`](crate::states::PayToken) and knows its corresponding
  previous [`State`].
- The customer knows the opening of commitments to the [`RevocationLock`],
  the new [`State`], and the corresponding `CloseState`.
- The new state from the commitment is correctly updated from the previous state
  (that is, the balances are updated by an agreed-upon amount)
- The committed [`RevocationLock`] and revealed [`Nonce`] are contained in the previous [`State`].
- The balances in the new [`State`] are non-negative.

*/
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayProof(());

/// Blinding factors for commitments associated with a particular payment.
#[derive(Debug)]
pub struct BlindingFactors {
    /// The blinding factor for a [`RevocationLockCommitment`] (associated with the previous [`State`])
    pub for_revocation_lock: RevocationLockBlindingFactor,
    /// The blinding factor for a [`StateCommitment`] (associated with the current [`State`]).
    pub for_pay_token: PayTokenBlindingFactor,
    /// The blinding factor for a [`CloseStateCommitment`] (associated with the current [`CloseState`]).
    pub for_close_state: CloseStateBlindingFactor,
}

impl PayProof {
    /**
    Form a new zero-knowledge [`PayProof`] object.

    It takes the previous [`State`] and corresponding [`PayToken`], and the new [`State`]. It also
    requires the blinding factors corresponding to commitments made on the previous [`State`]'s
    revocation lock, the [`PayToken`], and the [`CloseState`] derived from the given [`State`].

    Internally, it also prepares the signature proof on the given [`PayToken`]:

    - blinds and randomizes the [`PayToken`] to produce a [`PayTokenCommitment`] and
      corresponding [`PayTokenBlindingFactor`], and
    - forms a commitment to the old [`State`] underlying the [`PayToken`]

    This blinding factor is not used again during the protocol, so it doesn't leave this
    function.

    This function is typically called by the customer.
    */
    pub fn new(
        _rng: &mut impl Rng,
        _params: &customer::Config,
        _pay_token: PayToken,
        _old_state: State,
        _state: &State,
        _blinding_factors: BlindingFactors,
    ) -> Self {
        todo!();
    }

    /**
    Verify a PayProof against the given verification objects.

    This function is typically called by the merchant.
    */
    pub fn verify(
        &self,
        _params: &merchant::Config,
        _verification_objects: &PayProofVerification,
    ) -> Verification {
        todo!();
    }
}

/**
Commitment to the [`State`] underlying a [`PayToken`] for use in a [`PayProof`]

Note: this is a commitment to the [`State`] for use in the proof of knowledge of the opening
of a _signature_. This makes it different from a [`StateCommitment`], which is used in the
proof of knowledge of the opening of a _commitment_.
*/
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayTokenCommitment;

/// Collects the information a merchant needs to verify a [`PayProof`].
#[derive(Debug)]
pub struct PayProofVerification {
    /// Blinded, unused pay token from the previous [`State`].
    pub blinded_pay_token: BlindedPayToken,
    /// Commitment to the revocation lock in the previous [`State`].
    pub revocation_lock_commitment: RevocationLockCommitment,
    /// Commitment to the new channel [`State`].
    pub state_commitment: StateCommitment,
    /// Commitment to the new [`CloseState`].
    pub close_state_commitment: CloseStateCommitment,
    /// Expected nonce revealed at the beginning of Pay.
    pub nonce: Nonce,
    /// Expected payment amount.
    pub amount: crate::PaymentAmount,
}
