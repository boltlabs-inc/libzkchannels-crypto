//! Defines various state types used in the libzkchannels protocol.
//!
//! The primary type is a [`State`], which describes a zkChannel at a point in time. This object
//! is operated on throughout the protocol:
//! - A [`PayToken`] is a merchant signature on a [`State`], and allows a customer to continue making payments on a channel.
//! - A `CloseState` is a [`State`] with the payment-specific nonce removed. When signed, it can be used to claim funds on-chain
//! while maintaining payment privacy. To avoid de-synchronizing the `State` and `CloseState`, this library never produces a
//! `CloseState` directly.
//!
use serde::*;

use crate::nonce::*;
use crate::parameters::*;
use crate::revlock::*;
use crate::types::*;
use ps_blind_signatures::*;
use ps_signatures::Signature;

/// Channel identifier, binds each transaction to a specific customer.
#[derive(Debug, Clone, Copy)]
pub struct ChannelID;

/// Channel balance for merchant.
#[derive(Debug, Clone, Copy)]
pub struct MerchantBalance;

/// Channel balance for customer.
#[derive(Debug, Clone, Copy)]
pub struct CustomerBalance;

/// Amount of a single payment.
#[derive(Debug, Clone, Copy)]
pub struct PaymentAmount;

/// Describes the complete state of the channel with the given ID.
#[allow(unused)]
#[derive(Debug, Copy)]
pub struct State {
    cid: ChannelID,
    nonce: Nonce,
    revlock: RevocationLock,
    bal_m: MerchantBalance,
    bal_c: CustomerBalance,
}

impl Clone for State {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl State {
    /// Generates a new `State` with the given balances and ID.
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _cid: &ChannelID,
        _bal_m: &MerchantBalance,
        _bal_c: &CustomerBalance,
    ) -> Self {
        todo!();
    }

    /// Forms a new state, with balances updated by the given amount. Consumes the old state.
    pub fn update(self, _rng: &mut (impl CryptoRng + RngCore), _amt: &PaymentAmount) -> Self {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to a `State`.
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (StateCommitment, PayTokenBlindingFactor) {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to a `State`, but
    /// replacing the nonce with a "close" indicator to preserve payment privacy.
    pub fn commit_to_close_state(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (CloseStateCommitment, CloseStateBlindingFactor) {
        todo!();
    }
}

/// Commitment to a State.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StateCommitment(/*Commitment*/);

/// Commitment to a CloseState.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CloseStateCommitment(/*Commitment*/);

/// Signature on a CloseState - can be posted on-chain to close a channel.
#[derive(Debug, Clone, Copy)]
pub struct CloseStateSignature;

/// Blinded signature on a CloseState.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CloseStateBlindedSignature;

/// Blinding factor for a [`CloseStateCommitment`] and corresponding [`CloseStateBlindedSignature`].
#[derive(Debug, Clone, Copy)]
pub struct CloseStateBlindingFactor;

impl CloseStateBlindedSignature {
    /// Produces a signed close state so the customer can close a channel.
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &MerchantParameters,
        _com: &CloseStateCommitment,
    ) -> CloseStateBlindedSignature {
        todo!();
    }

    /// Unblinds a signature using the given blinding factor.
    pub fn unblind(&self, _bf: &CloseStateBlindingFactor) -> CloseStateSignature {
        todo!();
    }
}

impl CloseStateSignature {
    /// Verifies the merchant signature on a `CloseState` (derived from the given [`State`]).
    pub fn verify(&self, _param: &CustomerParameters, _state: &State) -> bool {
        todo!();
    }
}

/// Pay token allows a customer to make a payment; it is tied to a specific State and merchant
/// (via [`CustomerParameters`](crate::parameters::CustomerParameters::merchant_signing_pk)).
#[derive(Debug, Clone)]
pub struct PayToken(Signature);

/// Blinded signature on a [`PayToken`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindedPayToken(/*BlindedSignature*/);

/// Blinding factor for a [`PayTokenCommitment`] and corresponding [`BlindedPayToken`]
#[derive(Debug, Clone, Copy)]
pub struct PayTokenBlindingFactor(BlindingFactor);

/// Commitment to a [`PayToken`], used to validate a [`BlindedPayToken`]
///
/// Note: this is a commitment to the message in the form for a _signature_ proof
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayTokenCommitment;

impl BlindedPayToken {
    /// Produces a [`BlindedPayToken`] by blindly signing the `State` in the given commitment.
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &MerchantParameters,
        _com: &StateCommitment,
    ) -> Self {
        todo!();
    }

    /// Unblinds a `PayToken`.
    pub fn unblind(self, _bf: &PayTokenBlindingFactor) -> PayToken {
        todo!();
    }
}

impl PayToken {
    /// Verifies a `PayToken` against its corresponding [`State`].
    pub fn verify(&self, _param: &CustomerParameters, _state: &State) -> bool {
        todo!();
    }

    /// Prepares a `PayToken` for use in a [`PayProof`](crate::proofs::PayProof):
    /// - blinds and randomizes the `PayToken` to produce a [`BlindedPayToken`] and corresponding [`PayTokenBlindingFactor`]
    /// - forms a commitment to the `PayToken`'s underlying [`State`]
    pub fn prepare_for_proof(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
        _pt: &PayToken,
        _state: &State,
    ) -> (BlindedPayToken, PayTokenBlindingFactor, PayTokenCommitment) {
        todo!();
    }
}
