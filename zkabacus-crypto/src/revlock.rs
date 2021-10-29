/*!
This library describes revocation pairs, a formalization of hash locks.

A pair ([`RevocationLock`], [`RevocationSecret`]) satisfies two properties:

*Correctness*: A correctly generated revocation pair will always verify.

*Security*: Given a revocation lock, an adversary can generate a revocation secret that verifies
with only negligible probability (e.g. basically never).

*/
use crate::{merchant, types::*, Rng, Verification};
use zkchannels_crypto::{pedersen::Commitment, BlindingFactor, Message, SerializeElement};

use {
    ff::Field,
    serde::*,
    sha3::{Digest, Sha3_256},
    std::convert::{TryFrom, TryInto},
};

/// A verified revocation pair, which consists of a revocation secret and a corresponding revocation lock.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "UncheckedRevocationPair")]
#[allow(missing_copy_implementations)]
pub struct RevocationPair {
    /// A revocation lock.
    pub lock: RevocationLock,
    /// The associated revocation secret.
    pub secret: RevocationSecret,
}

#[derive(Debug, Deserialize)]
#[allow(missing_copy_implementations)]
struct UncheckedRevocationPair {
    lock: RevocationLock,
    secret: UncheckedRevocationSecret,
}

/// A revocation lock.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
#[allow(missing_copy_implementations)]
pub struct RevocationLock(#[serde(with = "SerializeElement")] Scalar);

/// A revocation secret.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationSecret {
    #[serde(with = "SerializeElement")]
    secret: Scalar,
    index: u8,
}

#[derive(Debug, Deserialize)]
struct UncheckedRevocationSecret {
    #[serde(with = "SerializeElement")]
    secret: Scalar,
    index: u8,
}

#[cfg(feature = "sqlite")]
zkchannels_crypto::impl_sqlx_for_bincode_ty!(RevocationLock);
#[cfg(feature = "sqlite")]
zkchannels_crypto::impl_sqlx_for_bincode_ty!(RevocationSecret);

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
pub struct RevocationLockCommitment(pub(crate) Commitment<G1Projective>);

/// Commitment randomness corresponding to a [`RevocationLockCommitment`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
pub struct RevocationLockBlindingFactor(pub(crate) BlindingFactor);

impl TryFrom<UncheckedRevocationPair> for RevocationPair {
    type Error = String;

    /// Try to convert an unchecked revocation pair into a verified revocation pair.
    fn try_from(unchecked: UncheckedRevocationPair) -> Result<Self, Self::Error> {
        let valid_pair = RevocationPair::try_from(unchecked.secret).unwrap();
        if unchecked.lock == valid_pair.lock {
            Ok(valid_pair)
        } else {
            Err("The revocation secret does not produce the provided revocation lock".to_string())
        }
    }
}

impl TryFrom<UncheckedRevocationSecret> for RevocationPair {
    type Error = String;

    /// Try to convert an unchecked revocation pair into a verified revocation pair.
    fn try_from(unchecked: UncheckedRevocationSecret) -> Result<Self, Self::Error> {
        // Compute the SHA3 hash of the byte representation of the unchecked revocation secret
        // (this byte conversion must match `RevocationSecret::as_bytes()`)
        let mut bytes = [unchecked.index; 33];
        bytes[0..32].copy_from_slice(&unchecked.secret.to_bytes());
        let digested = Sha3_256::digest(&bytes);

        // Determine if the result is a valid revocation lock, ie is a Scalar in canonical form (smaller than the modulus)
        let maybe_lock = Scalar::from_bytes(&<[u8; 32]>::try_from(&digested[..]).unwrap());

        if maybe_lock.is_some().into() {
            {
                let valid_secret = RevocationSecret {
                    secret: unchecked.secret,
                    index: unchecked.index,
                };
                let valid_lock = RevocationLock(maybe_lock.unwrap());
                Ok(RevocationPair {
                    secret: valid_secret,
                    lock: valid_lock,
                })
            }
        } else {
            Err("The revocation secret does not produce a valid revocation lock".to_string())
        }
    }
}

impl RevocationPair {
    /// Get the revocation lock.
    pub fn revocation_lock(&self) -> RevocationLock {
        self.lock
    }

    /// Get the revocation secret.
    pub fn revocation_secret(&self) -> RevocationSecret {
        self.secret
    }

    /// Create a new, random revocation pair.
    pub(crate) fn new(mut rng: impl Rng) -> Self {
        // Create a new, random revocation secret.
        let secret = Scalar::random(&mut rng);

        // This function could fail if the 256 possible values of `index` all fail to produce
        // valid revocation locks, but the likelihood of this is so vanishingly small that we
        // choose to ignore it
        let mut index: u8 = 0;
        loop {
            let maybe_secret = UncheckedRevocationSecret { secret, index };
            let maybe_pair = RevocationPair::try_from(maybe_secret);
            match maybe_pair {
                Ok(pair) => return pair,
                Err(_) => {
                    index += 1;
                }
            }
        }
    }
}

impl RevocationSecret {
    /// Encode the secret as bytes in little-endian order.
    pub fn as_bytes(&self) -> [u8; 33] {
        // Formatted as [scalar bytes , index]
        let mut bytes = [self.index; 33];
        bytes[0..32].copy_from_slice(&self.secret.to_bytes());
        bytes
    }
}

impl RevocationLock {
    // Convert a revocation lock to its canonical [`Message`] representation.
    pub(crate) fn to_message(&self) -> Message<1> {
        Message::from(self.to_scalar())
    }

    /// Convert a revocation lock to its canonical `Scalar` representation.
    pub(crate) fn to_scalar(&self) -> Scalar {
        self.0
    }

    /// Encode the lock as bytes in little-endian order.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Try to decode a [`RevocationLock`] from a set of bytes. Fails if the bytes are not a
    /// canonical little-endian representation of a [`Scalar`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Scalar::from_bytes(bytes).map(Self).into()
    }
}

impl RevocationLockCommitment {
    /// Validate the [`RevocationLockCommitment`] against the given parameters and blinding factor.
    ///
    /// This function verifies the opening of the commitment _and_ confirms that the [`RevocationLock`] is
    /// derived from the [`RevocationSecret`].
    pub(crate) fn verify_revocation_pair(
        &self,
        parameters: &merchant::Config,
        revocation_pair: &RevocationPair,
        revocation_lock_blinding_factor: &RevocationLockBlindingFactor,
    ) -> Verification {
        let opening_is_valid = self.0.verify_opening(
            parameters.revocation_commitment_parameters(),
            revocation_lock_blinding_factor.0,
            &Message::from(revocation_pair.lock.to_scalar()),
        );

        if opening_is_valid {
            Verification::Verified
        } else {
            Verification::Failed
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use {hex, rand::thread_rng};

  

    #[test]
    pub fn revlock_bytes_work() {
        let rp = RevocationPair::new(&mut thread_rng());
        let maybe_rl = RevocationLock::from_bytes(&rp.lock.as_bytes());

        assert_eq!(maybe_rl, Some(rp.lock))
    }

    #[test]
    pub fn revlock_generations_match() {
        let mut rng = thread_rng();
        for _ in 1..1000 {
            let rp = RevocationPair::new(&mut rng);

            // generate lock using `from_raw` method
            let digested = Sha3_256::digest(&rp.secret.as_bytes());
            let lock = Scalar::from_raw([
                u64::from_le_bytes(<[u8; 8]>::try_from(&digested[0..8]).unwrap()),
                u64::from_le_bytes(<[u8; 8]>::try_from(&digested[8..16]).unwrap()),
                u64::from_le_bytes(<[u8; 8]>::try_from(&digested[16..24]).unwrap()),
                u64::from_le_bytes(<[u8; 8]>::try_from(&digested[24..32]).unwrap()),
            ]);

            // compare to lock using `from_bytes` method
            assert_eq!(lock, rp.lock.to_scalar());
        }
    }

    #[test]
    pub fn checked_deserialization_works() {
        let scalar_str = "4dd70a569aa77c525dfc72b2dddd640ae1bee82b1430e63588ed71c183038d23";
        let secret =
            Scalar::from_bytes(&hex::decode(scalar_str).unwrap().try_into().unwrap()).unwrap();

        let unchecked_secret = UncheckedRevocationSecret { secret, index: 0 };
        assert!(RevocationPair::try_from(unchecked_secret).is_err());

        let valid_secret = UncheckedRevocationSecret { secret, index: 1 };
        assert!(RevocationPair::try_from(valid_secret).is_ok())
    }
}
