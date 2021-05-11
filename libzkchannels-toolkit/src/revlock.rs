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

impl RevocationLock {
    /// Generates a new revocation lock and its corresponding secret.
    pub fn generate_pair(_rng: &mut (impl CryptoRng + RngCore)) -> (Self, RevocationSecret) {
        todo!();
    }

    /// Validates a revocation pair.
    pub fn verify(&self, _rs: &RevocationSecret) -> bool {
        todo!();
    }

    /// Forms a commitment (and corresponding commitment randomness) to a RevocationLock.
    pub fn commit(
        &self,
        _rng: &mut (impl CryptoRng + RngCore),
        _param: &CustomerParameters,
    ) -> (RevocationLockCommitment, RevocationLockCommitmentRandomness) {
        todo!();
    }
}

impl RevocationLockCommitment {
    /// Validates a commitment to revocation lock against the given parameters and commitment randomness.
    pub fn decommit(
        &self,
        _param: &MerchantParameters,
        _rl: &RevocationLock,
        _bf: &RevocationLockCommitmentRandomness,
    ) -> bool {
        todo!();
    }
}
