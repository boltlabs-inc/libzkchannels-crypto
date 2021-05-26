/*!
This crate describes the zkAbacus protocol \[1\] and the cryptographic toolkit used to construct it.
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
pub mod customer;
pub mod merchant;
pub mod revlock;

pub use nonce::Nonce;
pub use proofs::EstablishProof;
pub use proofs::PayProof;
/// Rename cryptographically correct `BlindedPayToken` to the semantic `PayToken`.
pub use states::BlindedPayToken as PayToken;
/// Rename cryptographically correct `CloseStateBlindedSignature` to the semantic `ClosingSignature`.
pub use states::CloseStateBlindedSignature as ClosingSignature;
pub use states::{
    ChannelId, CloseStateCommitment, CustomerBalance, MerchantBalance, StateCommitment,
};

mod nonce;
mod proofs;
mod states;

#[allow(unused)]
mod types {
    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
    pub use libzkchannels_crypto::*;
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

/// Amount of a single payment.
#[derive(Debug, Clone, Copy)]
pub struct PaymentAmount;

impl PaymentAmount {
    /// Construct a *positive* payment amount from the customer to the merchant.
    pub fn pay_merchant(_amount: usize) -> Self {
        todo!()
    }

    /// Construct a *negative* payment amount from the merchant to the customer (i.e. a refund).
    pub fn pay_customer(_amount: usize) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {}
