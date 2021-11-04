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
    std::convert::{AsRef, TryFrom},
    thiserror::Error,
};

/// A verified revocation pair, which consists of a revocation secret and
/// a corresponding revocation lock.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(try_from = "UncheckedRevocationPair")]
#[allow(missing_copy_implementations)]
pub struct RevocationPair {
    /// A revocation lock.
    lock: RevocationLock,
    /// The associated revocation secret.
    secret: RevocationSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_copy_implementations)]
struct UncheckedRevocationPair {
    lock: RevocationLock,
    secret: UncheckedRevocationSecret,
}

/// A revocation lock.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub struct RevocationLock(#[serde(with = "SerializeElement")] Scalar);

/// A revocation secret.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub struct RevocationSecret {
    #[serde(with = "SerializeElement")]
    secret: Scalar,
    index: u8,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
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
pub struct RevocationLockBlindingFactor(pub(crate) BlindingFactor);

/// An error in producing a revocation pair.
#[derive(Debug, Copy, Clone, Error)]
pub enum Error {
    /// The provided revocation secret does not produce a valid revocation lock.
    #[error("The revocation secret does not produce a valid revocation lock")]
    InvalidSecret(),

    /// The provided revocation secret does not produce the input revocation lock.
    #[error("The revocation secret does not produce the provided revocation lock")]
    MismatchedPair(),
}

impl TryFrom<UncheckedRevocationPair> for RevocationPair {
    type Error = Error;

    /// Try to convert an unchecked revocation pair into a verified revocation pair.
    fn try_from(unchecked: UncheckedRevocationPair) -> Result<Self, Self::Error> {
        let valid_pair = RevocationPair::try_from(unchecked.secret)?;

        if unchecked.lock == valid_pair.lock {
            Ok(valid_pair)
        } else {
            Err(Error::MismatchedPair())
        }
    }
}

impl TryFrom<UncheckedRevocationSecret> for RevocationPair {
    type Error = Error;

    /// Try to convert an unchecked revocation secret into a verified revocation pair.
    fn try_from(unchecked: UncheckedRevocationSecret) -> Result<Self, Self::Error> {
        // Compute the SHA3 hash of the byte representation of the unchecked revocation secret
        // (this byte conversion must match `RevocationSecret::as_bytes()`)
        let digest = Sha3_256::new()
            .chain(unchecked.secret.to_bytes())
            .chain([unchecked.index])
            .finalize();

        // Determine if the result is a valid revocation lock,
        // ie is a Scalar in canonical form (smaller than the modulus)
        let maybe_lock = Scalar::from_bytes(digest.as_ref());

        if maybe_lock.is_some().into() {
            let valid_secret = RevocationSecret {
                secret: unchecked.secret,
                index: unchecked.index,
            };
            let valid_lock = RevocationLock(maybe_lock.unwrap());
            Ok(RevocationPair {
                secret: valid_secret,
                lock: valid_lock,
            })
        } else {
            Err(Error::InvalidSecret())
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
    pub(crate) fn to_message(self) -> Message<1> {
        Message::from(self.to_scalar())
    }

    /// Convert a revocation lock to its canonical `Scalar` representation.
    pub(crate) fn to_scalar(self) -> Scalar {
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
    use std::convert::TryInto;
    use {hex, rand::thread_rng};

    #[test]
    // Test computation of a verified revocation pair from
    // - a valid secret
    // - a valid pair
    pub fn revpair_is_correct() {
        let mut rng = thread_rng();

        for _ in 1..1000 {
            let rp = RevocationPair::new(&mut rng);

            let rs = UncheckedRevocationSecret {
                secret: rp.secret.secret,
                index: rp.secret.index,
            };

            let rp_from_unchecked_pair = RevocationPair::try_from(UncheckedRevocationPair {
                secret: rs,
                lock: rp.lock,
            })
            .unwrap();
            let rp_from_secret = RevocationPair::try_from(rs).unwrap();

            assert_eq!(rp_from_unchecked_pair, rp);
            assert_eq!(rp_from_secret, rp);
        }
    }

    #[test]
    pub fn revlock_bytes_work() {
        let mut rng = thread_rng();

        // Alway succeeds for a lock from a verified revocation pair
        for _ in 1..1000 {
            let rp = RevocationPair::new(&mut rng);
            let maybe_rl = RevocationLock::from_bytes(&rp.lock.as_bytes());

            assert_eq!(maybe_rl, Some(rp.lock))
        }
    }

    #[test]
    // Test that generating a new revocation pair results in a correct revocation lock
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
    // Check revocation pair from secret
    pub fn from_secret_works() {
        let scalar_str = "4dd70a569aa77c525dfc72b2dddd640ae1bee82b1430e63588ed71c183038d23";
        let secret =
            Scalar::from_bytes(&hex::decode(scalar_str).unwrap().try_into().unwrap()).unwrap();

        // Test that a specific invalid revocation secret produces the correct error
        // invalid secret
        let invalid_secret = UncheckedRevocationSecret { secret, index: 0 };
        assert!(matches!(
            RevocationPair::try_from(invalid_secret),
            Err(Error::InvalidSecret())
        ));

        // Test that a specific valid revocation secret produces a verified pair
        // valid secret
        let valid_secret = UncheckedRevocationSecret { secret, index: 1 };
        assert!(RevocationPair::try_from(valid_secret).is_ok())
    }

    #[test]
    // Check revocation pair from pair
    pub fn from_pair_works() {
        let scalar_str = "4dd70a569aa77c525dfc72b2dddd640ae1bee82b1430e63588ed71c183038d23";
        let secret =
            Scalar::from_bytes(&hex::decode(scalar_str).unwrap().try_into().unwrap()).unwrap();

        // Test that a specific invalid revocation secret produces the correct error
        // invalid secret
        let invalid_secret = UncheckedRevocationSecret { secret, index: 0 };

        // generate lock corresponding to invalid secret using `from_raw` method
        let invalid_digest = Sha3_256::new()
            .chain(invalid_secret.secret.to_bytes())
            .chain([invalid_secret.index])
            .finalize();

        let invalid_lock = Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[24..32]).unwrap()),
        ]);

        assert!(matches!(
            RevocationPair::try_from(UncheckedRevocationPair {
                secret: invalid_secret,
                lock: RevocationLock(invalid_lock)
            }),
            Err(Error::InvalidSecret())
        ));

        // Test that a specific valid revocation secret produces a verified pair
        // valid secret
        let valid_secret = UncheckedRevocationSecret { secret, index: 1 };
        // valid secret as bytes
        // generate lock corresponding to valid secret using `from_raw` method
        let digest = Sha3_256::new()
            .chain(valid_secret.secret.to_bytes())
            .chain([valid_secret.index])
            .finalize();

        let lock = Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&digest[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digest[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digest[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digest[24..32]).unwrap()),
        ]);

        assert!(RevocationPair::try_from(UncheckedRevocationPair {
            secret: valid_secret,
            lock: RevocationLock(lock)
        })
        .is_ok());

        // Test that a specific valid revocation secret with an invalid lock produces correct error
        // test that giving an invalid lock with a valid secret errors
        assert!(matches!(
            RevocationPair::try_from(UncheckedRevocationPair {
                secret: valid_secret,
                lock: RevocationLock(invalid_lock)
            }),
            Err(Error::MismatchedPair())
        ));
    }

    #[test]
    pub fn run_serialize_deserialize() {
        // Normal case
        let mut rng = thread_rng();
        for _ in 1..1000 {
            let rp = RevocationPair::new(&mut rng);
            let serialized_rp = bincode::serialize(&rp).unwrap();
            let deserialized_rp = bincode::deserialize(&serialized_rp).unwrap();

            assert_eq!(rp, deserialized_rp);
        }
    }

    #[test]
    pub fn failing_serialize_deserialize() {
        // Test bad pair
        let scalar_str = "4dd70a569aa77c525dfc72b2dddd640ae1bee82b1430e63588ed71c183038d23";
        let secret =
            Scalar::from_bytes(&hex::decode(scalar_str).unwrap().try_into().unwrap()).unwrap();

        // Test that a specific invalid revocation secret produces the correct error
        // invalid secret
        let invalid_secret = UncheckedRevocationSecret { secret, index: 0 };

        // generate lock corresponding to invalid secret using `from_raw` method
        let invalid_digest = Sha3_256::new()
            .chain(invalid_secret.secret.to_bytes())
            .chain([invalid_secret.index])
            .finalize();

        let invalid_lock = Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&invalid_digest[24..32]).unwrap()),
        ]);

        let unchecked_rp = UncheckedRevocationPair {
            secret: invalid_secret,
            lock: RevocationLock(invalid_lock),
        };

        let serialized_unchecked_rp = bincode::serialize(&unchecked_rp).unwrap();
        assert!(bincode::deserialize::<RevocationPair>(&serialized_unchecked_rp).is_err());
    }
}
