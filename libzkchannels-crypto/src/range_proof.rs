//! Implementation of range proofs by Camenisch, Chaabouni, and shelat [1], using single-message Pointcheval-
//! Sanders signatures [2] instead of the signature scheme in [1]. Uses the pairing groups BLS12-381 [3].
//! 
//! These are Schnorr-style zero knowledge proofs that prove a value is in range [0, u^l), for some parameters 
//! u and l.
//! 
//! This range proof cannot be used alone! It is only meaningful when used in conjunction with a [`CommitmentProof`]
//! or [`SignatureProof`], to show that the _message in that proof_ is within a given range.
//! 
//! 
//! ## References
//! 
//! 1: Jan Camenisch, Rafik Chaabouni, and abhi shelat. Efficient protocols for set membership and range proofs.
//! In Josef Pieprzyk, editor, Advances in Cryptology - ASIACRYPT 2008, pages 234–252, Berlin, Heidelberg,
//! 2008. Springer Berlin Heidelberg.
//! 
//! 2: David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor, Topics in
//! Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International Publishing, Cham, 2016.
//! 
//! 3: Dan Boneh, Sergey Gorbunov, Riad S. Wahby, Hoeteck Wee, and Zhenfei Zhang. BLS Signatures, revision 4. 
//! Internet draft, Internet Engineering Task Force, 2020.
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
//! 

use crate::{types::*, Error};
use crate::{ps_signatures::Signature, signature_proof::*, ps_keys::PublicKey};

/// The arity of our digits used in the range proof.
const RP_PARAMETER_U: u64 = 128;

/// Number of digits used in the range proof.
const RP_PARAMETER_L: usize = 7;

struct RangeProofParameters {
    digit_signatures: [Signature; RP_PARAMETER_U as usize], // length u
    public_key: PublicKey,
}

struct RangeProofBuilder {
    /// Partially-constructed PoK of the opening of signatures on each of the digits of the value
    digit_proof_builders: [SignatureProofBuilder; RP_PARAMETER_L], // length l
    /// Commitment scalar for the value
    pub commitment_scalar: Scalar, 
}

struct RangeProof {
    digit_proofs: [SignatureProof; RP_PARAMETER_L],
}

impl RangeProofBuilder {
    /// 
    pub fn generate_proof_commitments(n: i64) -> Result<Self, Error> {
        if n.is_negative() {
            return Err(Error::OutsideRange(n));
        }
        
        let mut digits = [0; RP_PARAMETER_L];
        let mut u = n as u64;
        for i in 0..RP_PARAMETER_L {
            digits[i] = u % RP_PARAMETER_U;
            u /= RP_PARAMETER_U;
        }
        
        todo!();
    }

    pub fn generate_proof_response(&self,) -> RangeProof {
        todo!();
    }
}

impl RangeProof {
    pub fn verify() {
        todo!()
    }
}