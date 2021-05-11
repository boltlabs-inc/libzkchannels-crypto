//! This library describes revocation pairs, a formalization of hash locks.
//!
//! A pair ([`RevocationLock`], [`RevocationSecret`]) satisfy two properties:
//! - Correctness: A revocation pair generated with [`generate_pair`](RevocationLock::generate_pair()) will always [`verify`](RevocationLock::verify()) correctly.
//! - Security: Given a revocation lock, an adversary can generate a correct revocation secret with negligible probability (e.g. basically never)
//!
use serde::*;

use crate::parameters::*;
use crate::types::*;

/// A revocation lock.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationLock;

/// A revocation secret.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationSecret;

/// A commitment to a [`RevocationLock`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationLockCommitment(/*Commitment*/);

/// Commitment randomness corresponding to a [`RevocationLockCommitment`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationLockCommitmentRandomness();

impl RevocationSecret {
    /// Create a new, random revocation secret.
    pub fn new(_rng: &mut impl Rng) -> Self {
        todo!()
    }

    /// Derives the [`RevocationLock`]  corresponding to this [`RevocationSecret`]
    pub fn revocation_lock(&self) -> RevocationLock {
        todo!();
    }
}

impl RevocationLock {
    /// Validates a revocation pair.
    pub fn verify(&self, _rs: &RevocationSecret) -> Verification {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to a RevocationLock.
    #[allow(unused)]
    pub(crate) fn commit(
        &self,
        _rng: &mut impl Rng,
        _param: &CustomerParameters,
    ) -> (RevocationLockCommitment, RevocationLockCommitmentRandomness) {
        todo!();
    }
}

impl RevocationLockCommitment {
    /// Validates a commitment to revocation lock against the given parameters and commitment
    /// randomness.
    pub fn verify(
        &self,
        _parameters: &MerchantParameters,
        _revocation_secret: &RevocationSecret,
        _revocation_lock: &RevocationLock,
        _revocation_lock_commitment_randomness: &RevocationLockCommitmentRandomness,
    ) -> Verification {
        todo!();
    }
}
