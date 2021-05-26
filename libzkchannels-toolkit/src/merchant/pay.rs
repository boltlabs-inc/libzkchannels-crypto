//! Cryptographic routines for processing payments on a channel.

use crate::{
    merchant::Config,
    nonce::Nonce,
    proofs::PayProof,
    revlock::*,
    states::{CloseStateCommitment, StateCommitment},
};

/// A channel that has approved a new payment, but has not revoked the previous channel state.
#[derive(Debug)]
pub struct Unrevoked<'a> {
    config: &'a Config,
    revocation_commitment: RevocationLockCommitment,
    state_commitment: StateCommitment,
}

impl Config {
    /**
    Issue a [`ClosingSignature`](crate::ClosingSignature) on the updated state, if the provided evidence is
    valid.

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

impl<'a> Unrevoked<'a> {
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
    ) -> Result<crate::PayToken, Unrevoked<'a>> {
        todo!();
    }
}
