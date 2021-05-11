/*!
 * This crate describes the cryptographic toolkit used directly by the libzkchannels protocol.
 * It defines contextual types as wrappers for the basic cryptographic primitves defined in `libzkchannels-crypto`.
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
    pub use rand::CryptoRng;
    pub use rand_core::RngCore;
}

#[cfg(test)]
mod tests {}
