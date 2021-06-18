//! Functionality for building challenge scalars.
//!
//! Supports challenges on proofs of knowledge of the opening of commitments, the opening of
//! signatures, and range proofs, both individually and in conjunctions. There is also support for
//! incorporating other public information into the challenge.

use crate::common::*;
use group::GroupEncoding;
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;

/// A trait implemented by types which can feed their public components into a [`ChallengeBuilder`].
pub trait ChallengeInput {
    /// Incorporate public components of this type into a [`ChallengeBuilder`].
    fn consume(&self, builder: &mut ChallengeBuilder);
}

impl<'a, T: ChallengeInput> ChallengeInput for &'a T {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        (**self).consume(builder);
    }
}

impl ChallengeInput for Scalar {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G1Affine {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G2Affine {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G1Projective {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

impl ChallengeInput for G2Projective {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_bytes());
    }
}

/// A challenge scalar for use in a Schnorr-style proof.
#[derive(Debug, Clone, Copy)]
pub struct Challenge(Scalar);

impl Challenge {
    /// Retrieve the internal scalar value.
    pub fn to_scalar(self) -> Scalar {
        self.0
    }
}

/// Holds state used when building a [`Challenge`] using the Fiat-Shamir heuristic, as in a
/// non-interactive Schnorr proof.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct ChallengeBuilder {
    hasher: Sha3_256,
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeBuilder {
    /// Initialize a new, empty challenge.
    pub fn new() -> Self {
        Self {
            hasher: Sha3_256::new(),
        }
    }

    /// Incorporate public data from some given type into the challenge.
    pub fn consume<T: ChallengeInput>(&mut self, object: &T) {
        object.consume(self);
    }

    /// A conveniently chainable variant of [`ChallengeBuilder::consume`].
    pub fn with<T: ChallengeInput>(mut self, object: &T) -> Self {
        object.consume(&mut self);
        self
    }

    /// Incorporate arbitrary bytes into the challenge.
    pub fn consume_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        self.hasher.update(bytes);
    }

    /// A conveniently chainable variant of [`ChallengeBuilder::consume_bytes`].
    pub fn with_bytes(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.consume_bytes(bytes);
        self
    }

    /// Consume the builder and generate a [`Challenge`] from the accumulated data.
    pub fn finish(self) -> Challenge {
        let mut digested = [0; 32];
        digested.copy_from_slice(self.hasher.finalize().as_ref());
        let scalar = Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[24..32]).unwrap()),
        ]);
        Challenge(scalar)
    }
}
