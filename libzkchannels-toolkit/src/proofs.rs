//! This describes the zero-knowledge proofs used in the Establish and Pay subprotocols of
//! zkChannels.
//!
//! These proofs are formed by the customer and demonstrate that they know the current state of the
//! channel and are modifying it appropriately. The merchant verifies the proofs, confirming that
//! the customer is behaving correctly without learning any information about the channel state.
use serde::*;

use crate::nonce::*;
use crate::parameters::*;
use crate::revlock::*;
use crate::states::*;
use crate::types::*;

/// An establish proof demonstrates that a customer is trying to initialize a channel correctly.
///
/// This is a Schnorr proof that makes the following guarantees in zero knowledge:
/// - The balances in the `State` match the previously-agreed-upon values.
/// - The commited `State` and `CloseState` are correctly formed relative to each other.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EstablishProof;

impl EstablishProof {
    /// Forms a new zero-knowledge [`EstablishProof`] object. Also produces commitments to the
    /// entities that make up the proof and their corresponding blinding factors.
    pub fn new<'a>(
        _rng: &mut impl Rng,
        _params: &CustomerParameters,
        _state: &'a State,
        _close_state_blinding_factor: Current<'a, CloseStateBlindingFactor>,
        _pay_token_blinding_factor: Current<'a, PayTokenBlindingFactor>,
    ) -> Self {
        todo!();
    }

    /// Verifies the [`EstablishProof`] against the provided verification objects.
    pub fn verify(
        &self,
        _params: &MerchantParameters,
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

/// A payment proof demonstrates that a customer is trying to make a valid payment on a channel.
///
/// This is a Schnorr proof that makes the following guarantees in zero knowledge:
///
/// - The old state is correctly updated from the new state by the given payment amount.
/// - The customer holds a valid [`PayToken`](crate::states::PayToken) and knows the old [`State`]
///   it corresponds to.
/// - The customer knows the opening of commitments to the [`RevocationLock`],  
///   the new [`State`], and the corresponding `CloseState`.  
/// - The committed [`RevocationLock`] and revealed [`Nonce`] are contained in the old [`State`].
/// - The balances in the new [`State`] are non-negative.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayProof;

impl PayProof {
    /// Forms a new zero-knowledge [`PayProof`] object. Also produces supporting commitments to the
    /// entities that make up the proof and their corresponding blinding factors.
    ///
    /// Prepares a signature proof on a [`PayToken`]:
    ///
    /// - blinds and randomizes the `PayToken` to produce a [`BlindedPayToken`] and corresponding
    ///   [`PayTokenBlindingFactor`]
    /// - forms a commitment to the `PayToken`'s underlying [`State`] Prepares commitment proofs on
    ///   a [`State`], corresponding [`CloseState`]
    pub fn new<'a>(
        _rng: &mut impl Rng,
        _params: &CustomerParameters,
        _old_state: State,
        _pay_token: PayToken,
        _state: &'a State,
        _revlock_commit_random: Current<'a, RevocationLockCommitmentRandomness>,
        _pay_token_blinding_factor: Current<'a, PayTokenBlindingFactor>,
        _close_state_blinding_factor: Current<'a, CloseStateBlindingFactor>,
    ) -> Self {
        todo!();
    }

    /// Verifies a PayProof of knowledge of opening of commitments with the given public parameters (nonce, amount).
    pub fn verify(
        &self,
        _params: &MerchantParameters,
        _verification_objects: &PayProofVerification,
    ) -> Verification {
        todo!();
    }
}

/// Collects the information a merchant needs to verify a [`PayProof`].
#[derive(Debug)]
pub struct PayProofVerification {
    /// Blinded, unused pay token from the merchant.
    pub _pay_token: BlindedPayToken,
    /// Commitment to an unused pay token.
    pub _pay_token_com: PayTokenCommitment,
    /// Commitment to the revocation lock in the old state.
    pub _rl_com: RevocationLockCommitment,
    /// Commitment to the new channel state.
    pub _state_com: StateCommitment,
    /// Commitment to the new close state.
    pub _close_state_com: CloseStateCommitment,
    /// Public nonce revealed at the beginning of Pay.
    pub _nonce: Nonce,
    /// Public payment amount.
    pub _amount: PaymentAmount,
}
