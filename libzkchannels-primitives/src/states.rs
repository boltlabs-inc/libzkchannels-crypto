use crate::nonce::*;
use crate::parameters::*;
use crate::revlock::*;
use crate::types::*;
use pedersen_commitments::*;
use ps_blind_signatures::BlindedSignature;
use ps_signatures::Signature;

/// Channel identifier, binds each transaction to a specific customer
pub struct ChannelID;

/// Channel balance for merchant
pub struct MerchantBalance;
/// Channel balance for customer
pub struct CustomerBalance;

/// Describes the complete state of the channel with the given ID
#[allow(unused)]
pub struct State {
    cid: ChannelID,
    nonce: Nonce,
    revlock: RevocationLock,
    bal_m: MerchantBalance,
    bal_c: CustomerBalance,
}

/// Commitment to a State
pub struct StateCommitment(Commitment);

impl State {
    /// Forms a commitment (and corresponding commitment randomness) to a State
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (StateCommitment, CommitmentRandomness) {
        todo!();
    }
}

/// Describes the state of the channel with the given ID
/// Suitable for publishing to the arbiter on channel closure
#[allow(unused)]
pub struct CloseState {
    cid: ChannelID,
    revlock: RevocationLock,
    bal_m: MerchantBalance,
    bal_c: CustomerBalance,
}

impl CloseState {
    /// Forms a commitment (and corresponding commitment randomness) to a CloseState
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (CloseStateCommitment, CommitmentRandomness) {
        todo!();
    }
}

/// Commitment to a CloseState
pub struct CloseStateCommitment(Commitment);

/// Signature on a CloseState
pub struct CloseStateSignature(Signature);

/// Blind signature on a CloseState
pub struct CloseStateBlindedSignature(BlindedSignature);
