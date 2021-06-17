/*!
This crate provides a cryptographic API for the zkAbacus protocol \[1\].
This API processes messages and produces cryptographic outputs for each step of the zkAbacus
protocol.
It **does not** handle communication between participants or long-term storage across channels.

The [`customer`] and [`merchant`] modules describe state machines for each party. A
customer maintains state over the lifetime of a channel that allows it to correctly update the
channel balances, make payments, and close the channel. The merchant has a comparatively simple
state machine: it operates primarily as a server, atomically processing requests from
customers but never retaining (or even learning) information about specific channels.

Internally, this crate also defines zkAbacus-aware cryptographic types as wrappers around the basic
cryptographic primitives defined in `libzkchannels-crypto`. Some of these types must be sent
between parties in the execution of zkAbacus; these are revealed publicly.

# References

1: [zkChannels Private Payments Protocol](https://github.com/boltlabs-inc/blindsigs-protocol).
Ch 3.3: Off-network channel protocol zkAbacus.
*/
#![warn(missing_docs)]
#![warn(missing_copy_implementations, missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(broken_intra_doc_links)]

#[cfg(feature = "sqlite")]
#[macro_use]
mod sqlite;

#[doc(hidden)]
pub mod internal;

pub mod customer;
pub mod merchant;
pub mod revlock;

use std::ops::BitAnd;

pub use nonce::Nonce;
pub use proofs::Context;
pub use proofs::EstablishProof;
pub use proofs::PayProof;

/// Rename cryptographically correct `BlindedPayToken` to the semantic `PayToken`.
pub use states::BlindedPayToken as PayToken;

/// Rename cryptographically correct `CloseStateBlindedSignature` to the semantic `ClosingSignature`.
pub use states::CloseStateBlindedSignature as ClosingSignature;

pub use states::{
    ChannelId, CloseState, CloseStateCommitment, CloseStateSignature, CustomerBalance,
    MerchantBalance, StateCommitment,
};

mod nonce;
mod proofs;
mod states;

#[allow(unused)]
mod types {
    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
    pub use zkchannels_crypto::*;
}

use crate::types::*;
use serde::*;
use std::convert::TryFrom;
use thiserror::*;

/// Possible error conditions returned from the ZkAbacus API.
#[derive(Debug, Error, Clone, Copy)]
pub enum Error {
    /// An amount was too large to be representable as a 64-bit signed integer.
    #[error("amount too large to be representable (greater than 2^63: {0})")]
    AmountTooLarge(u64),

    /// A payment would have created a negative balance.
    #[error("insufficient funds for operation")]
    InsufficientFunds,
}

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

impl From<bool> for Verification {
    fn from(b: bool) -> Self {
        match b {
            true => Verification::Verified,
            false => Verification::Failed,
        }
    }
}

impl BitAnd for Verification {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Verification::Verified, Verification::Verified) => Verification::Verified,
            (_, _) => Verification::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Balance(u64);

impl Balance {
    fn try_new(value: u64) -> Result<Self, Error> {
        if value > i64::MAX as u64 {
            Err(Error::AmountTooLarge(value))
        } else {
            Ok(Self(value))
        }
    }

    fn to_scalar(self) -> Scalar {
        Scalar::from(self.0)
    }

    /// Always returns a `u64` which is less than `i64::MAX`.
    fn into_inner(self) -> u64 {
        self.0 as u64
    }
}

/// Amount of a single payment.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PaymentAmount(i64);

impl PaymentAmount {
    /// Construct a zero payment amount that does not change the balances.
    pub fn zero() -> Self {
        Self(0)
    }

    /// Construct a *positive* payment amount from the customer to the merchant.
    pub fn pay_merchant(amount: u64) -> Result<Self, Error> {
        match i64::try_from(amount) {
            Ok(i) => Ok(Self(i)),
            Err(_) => Err(Error::AmountTooLarge(amount)),
        }
    }

    /// Construct a *negative* payment amount from the merchant to the customer (i.e. a refund).
    pub fn pay_customer(amount: u64) -> Result<Self, Error> {
        match i64::try_from(amount) {
            Ok(i) => Ok(Self(-i)),
            Err(_) => Err(Error::AmountTooLarge(amount)),
        }
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        if self.0.is_negative() {
            Scalar::zero() - Scalar::from(self.0.abs() as u64)
        } else {
            Scalar::from(self.0 as u64)
        }
    }

    /// Convert `PaymentAmount` to an [`i64`].
    pub fn to_i64(self) -> i64 {
        self.0
    }
}

/// The "CLOSE" scalar constant, used in place of a state's nonce to form a [`CloseStateCommitment`].
pub const CLOSE_SCALAR: Scalar = Scalar::from_raw([0, 0, 0, u64::from_le_bytes(*b"\0\0\0CLOSE")]);

#[cfg(test)]
mod tests {}
