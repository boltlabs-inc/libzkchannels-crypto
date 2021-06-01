/*!
This library describes revocation pairs, a formalization of hash locks.

A pair ([`RevocationLock`], [`RevocationSecret`]) satisfies two properties:

*Correctness*: A correctly generated revocation pair will always verify:

```ignore
# use libzkchannels_toolkit::{revlock::*, Verification};
# use rand::thread_rng;
let rs = RevocationSecret::new(&mut thread_rng());
let rl = rs.revocation_lock();
assert!(matches!(rl.verify(&rs), Verification::Verified));
```

FIXME(Marcella): un-ignore this doctest once things are implemented

*Security*: Given a revocation lock, an adversary can generate a revocation secret that verifies
with only negligible probability (e.g. basically never).

*/
use crate::{customer, types::*, Rng, Verification};
use serde::*;
use zkchannels_crypto::{
    message::BlindingFactor, pedersen_commitments::Commitment, SerializeElement,
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
/// [`RevocationLock`] and [`RevocationLockBlindingFactor`] that verifies with the commitment.
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationLockCommitment(Commitment<G1Projective>);

/// Commitment randomness corresponding to a [`RevocationLockCommitment`].
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationLockBlindingFactor(BlindingFactor);

#[allow(unused)]
impl RevocationSecret {
    /// Create a new, random revocation secret.
    pub(crate) fn new(_rng: &mut impl Rng) -> Self {
        todo!()
    }

    /// Derive the [`RevocationLock`]  corresponding to this [`RevocationSecret`]
    pub(crate) fn revocation_lock(&self) -> RevocationLock {
        todo!();
    }
}

#[allow(unused)]
impl RevocationLock {
    /// Validate a revocation pair.
    pub(crate) fn verify(&self, _rs: &RevocationSecret) -> Verification {
        todo!();
    }
}

#[allow(unused)]
impl RevocationLockCommitment {
    /// Validate the [`RevocationLockCommitment`] against the given parameters and blinding factor.
    ///
    /// This function decommits the commitment _and_ confirms that the [`RevocationLock`] is derived from the [`RevocationSecret`].
    pub(crate) fn verify(
        &self,
        _parameters: &customer::Config,
        _revocation_secret: &RevocationSecret,
        _revocation_lock: &RevocationLock,
        _revocation_lock_commitment_randomness: &RevocationLockBlindingFactor,
    ) -> Verification {
        todo!();
    }
}
