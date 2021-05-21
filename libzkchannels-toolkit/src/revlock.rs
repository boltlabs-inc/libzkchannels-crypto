//! This library describes revocation pairs, a formalization of hash locks.
//!
//! A pair ([`RevocationLock`], [`RevocationSecret`]) satisfy two properties:
//!
//! *Correctness*: A correctly generated revocation pair will always verify.
//!
//! ```ignore
//! # use libzkchannels_toolkit::{revlock::*, Verification};
//! # use rand::thread_rng;
//! let rs = RevocationSecret::new(&mut thread_rng());
//! let rl = rs.revocation_lock();
//! match rl.verify(&rs) {
//!     Verification::Verified => (),
//!     Verification::Failed => assert!(false),
//! }
//! ```
//!
//! NOTE: un-ignore this doctest once things are implemented
//!
//! *Security*: Given a revocation lock, an adversary can generate a correct revocation secret with negligible probability (e.g. basically never)
//!
use serde::*;

use crate::parameters::*;
use crate::{Rng, Verification};

/// A revocation lock.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationLock;

/// A revocation secret.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationSecret;

/// A commitment to a [`RevocationLock`].
///
/// This has the standard properties of a commitment scheme:
///
/// *Correctness*: A correctly-generated commitment will always verify.
///
/// *Hiding*: A `RevocationLockCommitment` does not reveal anything about the underlying [`RevocationLock`].
///
/// *Binding*: Given a `RevocationLockCommitment`, an adversary cannot efficiently generate a
/// [`RevocationLock`] and [`RevocationLockBlindingFactor`] that [`verify()`](RevocationLockCommitment::verify())s with the commitment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationLockCommitment(/*Commitment*/);

/// Commitment randomness corresponding to a [`RevocationLockCommitment`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationLockBlindingFactor();

impl RevocationSecret {
    /// Create a new, random revocation secret.
    pub fn new(_rng: &mut impl Rng) -> Self {
        todo!()
    }

    /// Derive the [`RevocationLock`]  corresponding to this [`RevocationSecret`]
    pub fn revocation_lock(&self) -> RevocationLock {
        todo!();
    }
}

impl RevocationLock {
    /// Validate a revocation pair.
    pub fn verify(&self, _rs: &RevocationSecret) -> Verification {
        todo!();
    }

    /// Form a commitment (and corresponding blinding factor) to a RevocationLock.
    #[allow(unused)]
    pub(crate) fn commit(
        &self,
        _rng: &mut impl Rng,
        _param: &CustomerParameters,
    ) -> (RevocationLockCommitment, RevocationLockBlindingFactor) {
        todo!();
    }
}

impl RevocationLockCommitment {
    /// Validate the [`RevocationLockCommitment`] against the given parameters and blinding factor.
    ///
    /// This function decommits the commitment _and_ confirms that the [`RevocationLock`] is derived from the [`RevocationSecret`].
    pub fn verify(
        &self,
        _parameters: &MerchantParameters,
        _revocation_secret: &RevocationSecret,
        _revocation_lock: &RevocationLock,
        _revocation_lock_commitment_randomness: &RevocationLockBlindingFactor,
    ) -> Verification {
        todo!();
    }
}
