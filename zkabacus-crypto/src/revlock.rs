/*!
This library describes revocation pairs, a formalization of hash locks.

A pair ([`RevocationLock`], [`RevocationSecret`]) satisfies two properties:

*Correctness*: A correctly generated revocation pair will always verify.

*Security*: Given a revocation lock, an adversary can generate a revocation secret that verifies
with only negligible probability (e.g. basically never).

*/
use crate::{customer, merchant, types::*, Rng, Verification};
use ff::Field;
use serde::*;
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;
use zkchannels_crypto::{
    message::{BlindingFactor, Message},
    pedersen_commitments::Commitment,
    SerializeElement,
};

/// A revocation lock.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationLock(#[serde(with = "SerializeElement")] Scalar);

/// A revocation secret.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationSecret(#[serde(with = "SerializeElement")] Scalar);

/// A commitment to a [`RevocationLock`].
///
/// This has the standard properties of a commitment scheme:
///
/// *Correctness*: A correctly-generated commitment will always verify.
///
/// *Hiding*: A `RevocationLockCommitment` does not reveal anything about the underlying
/// [`RevocationLock`].
///
/// *Binding*: Given a `RevocationLockCommitment`, an adversary cannot feasibly generate a
/// [`RevocationLock`] and [`RevocationLockBlindingFactor`] that verify with the commitment.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationLockCommitment(Commitment<G1Projective>);

/// Commitment randomness corresponding to a [`RevocationLockCommitment`].
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationLockBlindingFactor(BlindingFactor);

impl RevocationLockBlindingFactor {
    /// Generate a blinding factor uniformly at random.
    pub(crate) fn new(rng: &mut impl Rng) -> Self {
        Self(BlindingFactor::new(rng))
    }
}

impl RevocationSecret {
    /// Create a new, random revocation secret.
    pub(crate) fn new(rng: &mut impl Rng) -> Self {
        Self(Scalar::random(rng))
    }

    /// Derive the [`RevocationLock`] corresponding to this [`RevocationSecret`]
    pub(crate) fn revocation_lock(&self) -> RevocationLock {
        // Compute the SHA3 hash of the byte representation of this scalar, and then construct
        // another scalar from the result. This computation is entirely little-endian, so endianness
        // is consistent throughout.
        let bytes = self.0.to_bytes();
        let digested = Sha3_256::digest(&bytes);
        let scalar = Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[24..32]).unwrap()),
        ]);
        RevocationLock(scalar)
    }
}

impl RevocationLock {
    /// Validate a revocation pair.
    pub(crate) fn verify(&self, rs: &RevocationSecret) -> Verification {
        Verification::from(self.0 == rs.revocation_lock().0)
    }

    /// Form a commitment to the revocation lock.
    pub(crate) fn commit(
        &self,
        params: &customer::Config,
        revocation_lock_blinding_factor: &RevocationLockBlindingFactor,
    ) -> RevocationLockCommitment {
        RevocationLockCommitment(
            params
                .revocation_commitment_parameters
                .commit(
                    &Message::from(self.to_scalar()),
                    revocation_lock_blinding_factor.0,
                )
                .expect("mismatched lengths"),
        )
    }

    /// Convert a revocation lock to its canonical `Scalar` representation.
    pub(crate) fn to_scalar(&self) -> Scalar {
        self.0
    }
}

#[allow(unused)]
impl RevocationLockCommitment {
    /// Validate the [`RevocationLockCommitment`] against the given parameters and blinding factor.
    ///
    /// This function decommits the commitment _and_ confirms that the [`RevocationLock`] is
    /// derived from the [`RevocationSecret`].
    pub(crate) fn verify(
        &self,
        parameters: &merchant::Config,
        revocation_secret: &RevocationSecret,
        revocation_lock: &RevocationLock,
        revocation_lock_blinding_factor: &RevocationLockBlindingFactor,
    ) -> Verification {
        let verify_pair = revocation_lock.verify(revocation_secret);
        let verify_commitment = parameters
            .revocation_commitment_parameters
            .decommit(
                &Message::from(revocation_lock.to_scalar()),
                revocation_lock_blinding_factor.0,
                self.0,
            )
            .expect("mismatched lengths");

        if matches!(verify_pair, Verification::Verified) && verify_commitment {
            Verification::Verified
        } else {
            Verification::Failed
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;

    #[test]
    pub fn revlock_is_correct() {
        let rs = RevocationSecret::new(&mut thread_rng());
        let rl = rs.revocation_lock();
        assert!(matches!(rl.verify(&rs), Verification::Verified));
    }
}
