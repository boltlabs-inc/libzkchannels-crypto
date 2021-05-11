/*!
This crate provides an implementation of the following cryptographic primitives over the pairing-friendly curve BLS12-381:
- Pedersen Commitments instantiated using G1 and G2.
- Schnorr-style zero-knowledge proofs instantiated using G1 and G2.
- Pointcheval Sanders signatures and zero-knowledge proof of knowledge of a signature (CT-RSA 2016).
- Camenisch, Chaabouni, and shelat's range proofs (Asiacrypt 2008) instantiated using Pointcheval Sanders signatures.
*/

#![warn(missing_docs)]
#![warn(missing_copy_implementations, missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(broken_intra_doc_links)]
pub mod message;
pub mod pedersen_commitments;
pub mod ps_blind_signatures;
pub mod ps_keys;
pub mod ps_signatures;

mod types {
    pub use crate::message::*;
    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

    /// Trait synonym for a cryptographically secure random number generator.
    pub trait Rng: rand::CryptoRng + rand::RngCore {}
    impl<T: rand::CryptoRng + rand::RngCore> Rng for T {}

}
