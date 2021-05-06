use crate::types::*;
use std::ops::Deref;

/// Fixed-length message type used across schemes
#[derive(Debug, Clone)]
pub struct Message(Vec<Scalar>);

impl Deref for Message {
    type Target = [Scalar];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Message {
    pub fn new(m: Vec<Scalar>) -> Self {
        Message(m)
    }
}
