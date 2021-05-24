//! Defines a fixed-length message type for use across schemes in this crate.
use crate::{types::*, SerializeElement};
use ff::Field;
use serde::*;
use std::ops::Deref;

/// Fixed-length message type used across schemes.
#[derive(Debug, Clone)]
pub struct Message(Vec<Scalar>);

impl Deref for Message {
    type Target = [Scalar];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Message {
    /// Create a new message from a Vec<Scalar>.
    pub fn new(m: Vec<Scalar>) -> Self {
        Message(m)
    }
}

/// Blinding factor for a commitment, message, or signature.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlindingFactor(#[serde(with = "SerializeElement")] pub(crate) Scalar);

impl BlindingFactor {
    /// Generate a new blinding factor uniformly at random from the set of possible [`Scalar`]s.
    pub fn new(rng: &mut impl Rng) -> Self {
        Self(Scalar::random(rng))
    }
}
