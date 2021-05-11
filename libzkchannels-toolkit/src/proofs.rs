//! This describes the zero-knowledge proofs used in the Establish and Pay subprotocols of zkChannels.
//!
//! These proofs are formed by the customer and demonstrate that they know the current state of the channel and are
//! modifying it appropriately. The merchant verifies the proofs, confirming that the customer is behaving correctly
//! without learning any information about the channel state.
//!
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
    /// Forms a new zero-knowledge [`EstablishProof`] object. Also produces commitments to the entities
    /// that make up the proof and their corresponding blinding factors.
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _params: &CustomerParameters,
        _state: &State,
    ) -> (
        Self,
        CloseStateCommitment,
        CloseStateBlindingFactor,
        StateCommitment,
        PayTokenBlindingFactor,
    ) {
        todo!();
    }

    /// Verifies the [`EstablishProof`] against the provided verification objects.
    pub fn verify(
        &self,
        _params: &MerchantParameters,
        _verification_objects: &EstablishProofVerification,
    ) -> bool {
        todo!();
    }
}

/// Collects the information a merchant needs to verify a [`EstablishProof`].
#[derive(Debug, Clone, Copy)]
pub struct EstablishProofVerification {
    /// Commitment to a [`State`].
    pub state_com: StateCommitment,
    /// Commitment to a `CloseState`.
    pub close_state_com: CloseStateCommitment,
    /// Expected channel ID.
    pub cid: ChannelID,
    /// Expected merchant balance.
    pub bal_m: MerchantBalance,
    /// Expected customer balance.
    pub bal_c: CustomerBalance,
}

/// A payment proof demonstrates that a customer is trying to make a valid payment on a channel.
///
/// This is a Schnorr proof that makes the following guarantees in zero knowledge:
/// - The old state is correctly updated from the new state by the given payment amount.
/// - The customer holds a valid [`PayToken`](crate::states::PayToken) and knows the old [`State`] it corresponds to.
/// - The customer knows the opening of commitments to the [`RevocationLock`],  
/// the new [`State`], and the corresponding `CloseState`.  
/// - The committed [`RevocationLock`] and revealed [`Nonce`] are contained in the old [`State`].
/// - The balances in the new [`State`] are non-negative.
///
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayProof;

impl PayProof {
    /// Forms a new zero-knowledge [`PayProof`] object. Also produces supporting commitments to the entities
    /// that make up the proof and their corresponding blinding factors.
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _params: &CustomerParameters,
        _rl: &RevocationLock,
        _old_state: State,
        _state: &State,
    ) -> (
        Self,
        RevocationLockCommitment,
        RevocationLockCommitmentRandomness,
        StateCommitment,
        PayTokenBlindingFactor,
        CloseStateCommitment,
        CloseStateBlindingFactor,
    ) {
        todo!();
    }

    /// Verifies a PayProof of knowledge of opening of commitments with the given public parameters (nonce, amount).
    pub fn verify(
        &self,
        _params: &MerchantParameters,
        _verification_objects: &PayProofVerification,
    ) -> bool {
        todo!();
    }
}

/// Collects the information a merchant needs to verify a [`PayProof`].
#[derive(Debug, Clone, Copy)]
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
