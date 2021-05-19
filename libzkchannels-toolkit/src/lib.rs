/*!
This crate describes the zkAbacus protocol [1] and the cryptographic toolkit used to construct it.
It defines contextual types as wrappers for the basic cryptographic primitives defined in `libzkchannels-crypto`.

 # References

 1: zkChannels Private Payments Protocol. Ch 3.3: Off-network channel protocol zkAbacus.
 URL: https://github.com/boltlabs-inc/blindsigs-protocol
 */
#![warn(missing_docs)]
#![warn(missing_copy_implementations, missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(broken_intra_doc_links)]
pub mod nonce;
pub mod parameters;
pub mod proofs;
pub mod revlock;
pub mod states;

#[allow(unused)]
mod types {
    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
    pub use libzkchannels_crypto::*;
}

use std::marker::PhantomData;
use std::ops::Deref;

/// Trait synonym for a cryptographically secure random number generator.
pub trait Rng: rand::CryptoRng + rand::RngCore {}
impl<T: rand::CryptoRng + rand::RngCore> Rng for T {}

/// The result of a verification of some property.
#[derive(Debug, Clone, Copy)]
#[must_use = "the result of a verification should always be checked"]
pub enum Verification {
    /// A verification succeeded.
    Verified,
    /// A verification failed.
    Failed,
}

/// An owned value tied to a phantom `'a` lifetime, which can only be used while its
/// corresponding state is still current.
#[derive(Debug, Clone, Copy)]
pub struct Current<'a, T> {
    lifetime: PhantomData<&'a ()>,
    inner: T,
}

#[allow(unused)]
impl<'a, T> Current<'a, T> {
    /// Create a new [`Current`] value (not exposed in public API).
    pub(crate) fn new(inner: T) -> Current<'a, T> {
        Current {
            lifetime: PhantomData,
            inner,
        }
    }

    /// Remember a [`Current`] value after this iteration of the state.
    pub(crate) fn remember(this: Current<'a, T>) -> T {
        this.inner
    }
}

impl<'a, T> Deref for Current<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// An owned value tied to a phantom `'a` lifetime, which can only be used while its
/// corresponding state is still current.
#[derive(Debug, Clone, Copy)]
pub struct Previous<'a, T> {
    lifetime: PhantomData<&'a ()>,
    inner: T,
}

#[allow(unused)]
impl<'a, T> Previous<'a, T> {
    /// Create a new [`Previous`] value (not exposed in public API).
    pub(crate) fn new(inner: T) -> Previous<'a, T> {
        Previous {
            lifetime: PhantomData,
            inner,
        }
    }

    /// Remember a [`Current`] value after this iteration of the state.
    pub(crate) fn remember(this: Previous<'a, T>) -> T {
        this.inner
    }
}

impl<'a, T> Deref for Previous<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {}
