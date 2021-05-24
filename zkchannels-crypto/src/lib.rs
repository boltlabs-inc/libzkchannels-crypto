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

pub mod challenge;
pub mod commitment_proof;
pub mod message;
pub mod pedersen_commitments;
pub mod ps_blind_signatures;
pub mod ps_keys;
pub mod ps_signatures;
pub mod range_proof;
pub mod signature_proof;

use thiserror::*;

/// Error types that may arise from cryptographic operations.
#[derive(Debug, Error, Clone, Copy)]
pub enum Error {
    /// Raised when a range proof is constructed on an out-of-range value.
    #[error("tried to build a range proof on a negative value ({0})")]
    OutsideRange(i64),
}

mod serde;

pub use crate::serde::{SerializeElement, SerializeG1, SerializeG2};

mod types {
    pub use crate::message::*;
    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

    /// A trait synonym for a cryptographically secure random number generator. This trait is
    /// blanket-implemented for all valid types and will never need to be implemented by-hand.
    pub trait Rng: rand::CryptoRng + rand::RngCore {}
    impl<T: rand::CryptoRng + rand::RngCore> Rng for T {}
}

#[cfg(test)]
mod tests {
    use crate::{ps_keys::*, ps_signatures::*, types::*};
    use bls12_381::Scalar;
    use ff::Field;
    use std::iter;

    #[test]
    fn make_keypair() {
        let mut rng = rand::thread_rng();
        let _kp = KeyPair::new(3, &mut rng);
    }

    #[test]
    fn signing_is_correct() {
        let mut rng = rand::thread_rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let sig = kp.try_sign(&mut rng, &msg).unwrap();
        assert!(
            kp.verify(&msg, &sig),
            "Signature didn't verify!! {:?}, {:?}",
            kp,
            msg
        );
    }
}
