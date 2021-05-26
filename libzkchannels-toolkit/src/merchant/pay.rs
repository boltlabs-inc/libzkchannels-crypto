/*!
Cryptographic functionality for the merchant side of the pay protocol as described in zkAbacus.
*/

use crate::{
    merchant::{Config, Ready},
    nonce::Nonce,
    proofs::PayProof,
    revlock::*,
    states::{BlindedPayToken, CloseStateBlindedSignature, CloseStateCommitment, StateCommitment},
};

/// A channel that has approved a new payment, but has not revoked the previous channel state.
#[derive(Debug)]
pub struct Unrevoked {
    config: Config,
    revocation_commitment: RevocationLockCommitment,
    state_commitment: StateCommitment,
}

impl Ready {
    /**
    Issue a [`CloseStateBlindedSignature`] on the updated state, if the provided evidence is
    valid.

    This should only be called if the [`Nonce`] has never been seen before.

    This will fail if the [`PayProof`] is not verifiable with the provided commitments and [`Nonce`]
    */
    pub fn allow_payment(
        self,
        _nonce: &Nonce,
        _pay_proof: PayProof,
        _revocation_commitment: RevocationLockCommitment,
        _state_commitment: StateCommitment,
        _close_state_commitment: CloseStateCommitment,
    ) -> Result<(Unrevoked, CloseStateBlindedSignature), Ready> {
        todo!();
    }
}

impl Unrevoked {
    /**
    Issue a pay token on the updated state, if the revocation information is well-formed.

    This should only be called if the revocation lock has never been seen before.

    This will fail if the revocation information is not well-formed (e.g. the revocation lock does
    not match the revocation secret; or it does not match the stored revocation commitment).
    */
    pub fn revoke(
        self,
        _revocation_lock: &RevocationLock,
        _revocation_secret: &RevocationSecret,
        _revocation_blinding_factor: &RevocationLockBlindingFactor,
    ) -> Result<(Ready, BlindedPayToken), Unrevoked> {
        todo!();
    }
}
