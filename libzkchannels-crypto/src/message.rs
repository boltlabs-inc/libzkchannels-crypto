//! Defines a fixed-length message type for use across schemes in this crate.
use crate::types::*;
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
