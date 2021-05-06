use crate::nonce::*;
use crate::parameters::*;
use crate::revlock::*;
use crate::types::*;
use pedersen_commitments::*;
use ps_blind_signatures::*;
use ps_signatures::Signature;

/// Channel identifier, binds each transaction to a specific customer
pub struct ChannelID;

/// Channel balance for merchant
pub struct MerchantBalance;
/// Channel balance for customer
pub struct CustomerBalance;

/// Payment amount
pub struct PaymentAmount;

/// Describes the complete state of the channel with the given ID
#[allow(unused)]
pub struct State {
    cid: ChannelID,
    nonce: Nonce,
    revlock: RevocationLock,
    bal_m: MerchantBalance,
    bal_c: CustomerBalance,
}

impl State {
    /// Generates a new State with the given balances and ID
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _cid: &ChannelID,
        _bal_m: &MerchantBalance,
        _bal_c: &CustomerBalance,
    ) -> Self {
        todo!();
    }

    /// Forms a new state, with balances updated by the given amount
    pub fn update(&self, _rng: &mut (impl CryptoRng + RngCore), _amt: &PaymentAmount) -> Self {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to a State
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (StateCommitment, PayTokenBlindingFactor) {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to the state, but
    /// replacing the nonce with a "close" indicator to preserve payment privacy
    pub fn commit_to_close_state(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (CloseStateCommitment, CloseStateBlindingFactor) {
        todo!();
    }
}

/// Commitment to a State
pub struct StateCommitment(Commitment);

/// Commitment to a CloseState - describes the state as will be posted on-chain to close a channel
pub struct CloseStateCommitment(Commitment);

/// Signature on a CloseState - can be posted on-chain to close a channel
pub struct CloseStateSignature;

/// Blinded signature on a CloseState
pub struct CloseStateBlindedSignature;
pub struct CloseStateBlindingFactor;

impl CloseStateBlindedSignature {
    /// produces a signed close state so the customer can close a channel
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &MerchantParameters,
        _com: CloseStateCommitment,
    ) -> CloseStateBlindedSignature {
        todo!();
    }

    /// unblinds signature
    pub fn unblind(&self, _bf: &CloseStateBlindingFactor) -> CloseStateSignature {
        todo!();
    }
}

impl CloseStateSignature {
    pub fn verify(&self, _param: &CustomerParameters, _state: &State) -> bool {
        todo!();
    }
}

/// Pay token allows a customer to make a payment; it is tied to a specific State and merchant (via CustomerParameters.merchant_signing_pk)
pub struct PayToken(Signature);

/// Blind signature on a PayToken
pub struct BlindedPayToken(BlindedSignature);

/// Blinding factor corresponding to a BlindedPayToken
pub struct PayTokenBlindingFactor(BlindingFactor);

/// Commitment to a PayToken, used to validate a BlindedPayToken
/// Note: this is a commitment to the message in a _signature_ proof
pub struct PayTokenCommitment;

impl BlindedPayToken {
    /// produces a pay token by blindly signing the state in the given commitment
    pub fn new(
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &MerchantParameters,
        _com: &StateCommitment,
    ) -> Self {
        todo!();
    }

    /// Unblinds a PayToken
    pub fn unblind(&self, _bf: &PayTokenBlindingFactor) -> PayToken {
        todo!();
    }
}

impl PayToken {
    /// verifies a PayToken against its corresponding State
    pub fn verify(&self, _param: &CustomerParameters, _state: &State) -> bool {
        todo!();
    }

    /// Prepares a PayToken for use in a PayProof:
    /// - blinds and randomizes the PayToken
    /// - forms a signature-proof commitment to the state corresponding to the PayToken
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
