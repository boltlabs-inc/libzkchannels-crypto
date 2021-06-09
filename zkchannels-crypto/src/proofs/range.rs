//! Schnorr-style proofs of knowledge that a value lies within the range `[0, 2^63)`.
//!
//! **This range proof cannot be used alone!** It is only meaningful when used in conjunction with a
//! [`CommitmentProof`](crate::proofs::CommitmentProof) or [`SignatureProof`], to show that the
//! message _in that proof_ lies within the given range.
//!
//! These are Camenish, Chaabouni, and shelat-style range proofs \[1\] built using standard Schnorr.
//! They prove a value is in range `[0, u^l)`, for some parameters `u` and `l`. This implementation
//! selects `u`, `l` to produce proofs for the range `[0, 2^63)` It also uses single-message
//! Pointcheval-Sanders signatures \[2\] instead of the signature scheme in \[1\]. It uses the
//! pairing group defined in BLS12-381 \[3\]. Note that this implementation only supports the range
//! `[0, 2^63]`; \[1\] provides a technique to show a value lies in an arbitrary interval `[a,b]`,
//! but that is not supported here.
//!
//! ## Intuition
//! The prover writes the value in `u`-ary. That is, a value `B` is written `B0 .. Bl`, where each
//! `Bi` is in the range `[0,u)`. These have the property that `B = sum( u^i * Bi )`.
//!
//! The prover shows they know a signature on each digit and that the digits are a correct `u`-ary
//! representation of the corresponding value. Signatures on each possible digit are provided by the
//! verifier: they use a one-time-use range proof key to sign the values 0 to `u` and publish them.
//!
//! This module provides tools to produce a PoK over the digit signatures for a given value.
//! However, it alone *does not* show that the `u`-ary representation matches a meaningful value!
//! This step requires a conjunction with a [`CommitmentProof`](crate::proofs::CommitmentProof) or
//! [`SignatureProof`].
//!
//! This type of proof requires additional parameters (a range proof public key) and a more
//! computationally intensive setup phase by the verifier (to generate `u` signatures). Luckily,
//! this only has to be done once over the lifetime of _all_ range proofs. It is important that the
//! verifier does not reuse the range proof key for any other operations, especially signing
//! operations: the security of the proof depends on the fact that the digit signatures can _only_
//! be on valid `u`-ary digits.
//!
//! ## Expected use
//! Suppose you wish to show that the `j`th message element in a
//! [`CommitmentProof`](crate::proofs::CommitmentProof) is within the given range.
//!
//! 1. *Initiate the range proof.* Call [`RangeProofBuilder::generate_proof_commitments()`], passing
//!     the value you wish to show is in a range.
//!
//! 2. *Link to the commitment proof*. The resulting [`RangeProofBuilder`] contains a field called
//!     `commitment_scalar`. Place this element in the `j`th index of
//!     `conjunction_commitment_scalars` and use it to [generate the CommitmentProof`
//!     commitments](crate::proofs::CommitmentProofBuilder::generate_proof_commitments()).
//!
//! 3. *Generate a challenge*. In an interactive proof, the prover obtains a random challenge from
//!     the verifier. However, it is standard practice to use the Fiat-Shamir heuristic to transform
//!     an interactive proof into a non-interactive proof; see [`Challenge`] for details.
//!
//! 4. *Complete the proofs*. Call the `generate_proof_response()` function for the [commitment
//!     proof](crate::proofs::CommitmentProofBuilder::generate_proof_response()) and the [range
//!     proof](RangeProofBuilder::generate_proof_response()).
//!
//! To verify a range proof, the verifier must check the following:
//!
//! 1. The commitment proof is correctly constructed.
//! 2. The range proof digits are correctly constructed.
//! 3. The value in the commitment proof corresponds to the digits in the range proof.
//!
//! To do so, the verifier should first reconstruct the challenge. Verify 1 using the standard
//! commitment proof [verification
//! function](crate::proofs::CommitmentProof::verify_knowledge_of_opening_of_commitment()). To
//! verify 2 and 3, retrieve the `j`th response scalar using
//! [`CommitmentProof::conjunction_response_scalars()`](crate::proofs::CommitmentProof::conjunction_response_scalars())
//! and pass it to [`verify_range_proof()`](RangeProof::verify_range_proof())
//!
//! The approach for a signature proof is similar.
//!
//! ## References
//!
//! 1. Jan Camenisch, Rafik Chaabouni, and abhi shelat. Efficient protocols for set membership and
//!    range proofs. In Josef Pieprzyk, editor, Advances in Cryptology - ASIACRYPT 2008, pages
//!    234–252, Berlin, Heidelberg,
//! 2008. Springer Berlin Heidelberg.
//!
//! 2. David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor,
//!    Topics in Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International
//!    Publishing, Cham, 2016.
//!
//! 3. Dan Boneh, Sergey Gorbunov, Riad S. Wahby, Hoeteck Wee, and Zhenfei Zhang. BLS Signatures,
//!    revision 4. Internet draft, Internet Engineering Task Force, 2020.
//!    https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04

use crate::{
    common::*,
    pointcheval_sanders::*,
    proofs::{Challenge, SignatureProof, SignatureProofBuilder},
    Error,
};
use arrayvec::ArrayVec;

/// The arity of our digits used in the range proof.
const RP_PARAMETER_U: u64 = 128;

/// Number of digits used in the range proof.
const RP_PARAMETER_L: usize = 9;

/// Parameters for use in a [`RangeProof`].
///
/// These should be generated by a trusted party (e.g. the verifier) and can be shared with any potential provers.
#[allow(unused)]
#[derive(Debug)]
pub struct RangeProofParameters {
    /// A signature on every `u`-ary digit
    digit_signatures: [Signature; RP_PARAMETER_U as usize],
    /// Public key corresponding _exclusively with the signatures above.
    public_key: PublicKey<1>,
}

impl RangeProofParameters {
    /// Generate new parameters for use in range proofs.
    ///
    /// Note that this generates a [`KeyPair`](crate::pointcheval_sanders::KeyPair) to produce the
    /// `digit_signatures`, but discards the secret half after use. This is to prevent misuse; it
    /// should never be used again.
    pub fn new(rng: &mut impl Rng) -> Self {
        // Workaround for not being able to use `as` in const type variables for now.
        const RP_PARAMETER_U_AS_USIZE: usize = RP_PARAMETER_U as usize;

        let keypair = KeyPair::<1>::new(rng);
        let digit_signatures = (0..RP_PARAMETER_U)
            .map(|i| keypair.sign(&mut *rng, &Scalar::from(i).into()))
            .collect::<ArrayVec<_, RP_PARAMETER_U_AS_USIZE>>();

        Self {
            digit_signatures: digit_signatures.into_inner().expect("known length"),
            public_key: keypair.public_key().clone(),
        }
    }
}

/// A partially-built [`RangeProof`].
///
/// It contains the output of the PoK of signatures setup phase and the Schnorr commitment phase.
#[allow(unused)]
#[derive(Debug)]
pub struct RangeProofBuilder {
    /// Partially-constructed PoK of the opening of signatures on each of the digits of the value.
    pub(crate) digit_proof_builders: [SignatureProofBuilder<1>; RP_PARAMETER_L],
    /// Commitment scalar for the value being proven in the range.
    pub commitment_scalar: Scalar,
}

/// Proof of knowledge that a `u`-ary representation of a value falls within the given range.
/// This is **not** a complete range proof unless supplied in conjunction with a
/// [`CommitmentProof`](crate::proofs::CommitmentProof) or a [`SignatureProof`].
#[allow(unused)]
#[derive(Debug)]
pub struct RangeProof {
    /// Complete PoKs of the opening of a signature on each digit of the value.
    pub digit_proofs: [SignatureProof<1>; RP_PARAMETER_L],
}

#[allow(unused)]
impl RangeProofBuilder {
    /// Run the commitment phase of a Schnorr-style range proof on the value, to show that
    /// `0 <= value < 2^63`.
    pub fn generate_proof_commitments(
        value: i64,
        params: &RangeProofParameters,
        rng: &mut impl Rng,
    ) -> Result<Self, Error> {
        // Make sure value lies within the correct range: a normal i64 is in the range [-2^63, 2^63).
        // A non-negative i64 must be in the range [0, 2^63).
        if value.is_negative() {
            return Err(Error::OutsideRange(value));
        }
        // It is now safe to convert to u64 (the value cannot be in the overflow range [2^63, 2^64).)
        let mut decomposing_value = value as u64;

        // Decompose the value into digits.
        let mut digits = [0; RP_PARAMETER_L];
        for digit in &mut digits {
            *digit = decomposing_value % RP_PARAMETER_U;
            decomposing_value /= RP_PARAMETER_U;
        }

        // Compute signature proof builders on each digit.
        let digit_proof_builders: [SignatureProofBuilder<1>; RP_PARAMETER_L] = digits
            .iter()
            .map(|&digit| {
                SignatureProofBuilder::generate_proof_commitments(
                    rng,
                    // N.B. u64s are being encoded to `Scalar`s using the builtin bls12_381
                    // `From<u64>` implementation.
                    Scalar::from(digit).into(),
                    params.digit_signatures[digit as usize],
                    &[None],
                    &params.public_key,
                )
            })
            .collect::<Result<ArrayVec<_, RP_PARAMETER_L>, Error>>()?
            .into_inner()
            .expect("impossible; len will always be RP_PARAMETER_L");

        // Construct cumulative commitment scalar for value from the commitment scalars of its digits.
        let mut commitment_scalar = Scalar::zero();
        // u_pow holds the term u^j for j = 0 .. RP_PARAMETER_L
        let mut u_pow = Scalar::one();
        // Compute sum ( u^j * commitment_scalar[j] )
        for proof_builder in &digit_proof_builders {
            // The message here is always of length 1, so it's always okay to index it at the 0th element.
            commitment_scalar += u_pow * proof_builder.conjunction_commitment_scalars()[0];
            u_pow *= Scalar::from(RP_PARAMETER_U);
        }

        Ok(Self {
            digit_proof_builders,
            commitment_scalar,
        })
    }

    /// Run the response phase of a Schnorr-style proof of knowledge that a value is in a range.
    pub fn generate_proof_response(self, challenge: Challenge) -> Result<RangeProof, Error> {
        let digit_proofs = ArrayVec::from(self.digit_proof_builders)
            .into_iter()
            .map(|builder| builder.generate_proof_response(challenge))
            .collect::<Result<ArrayVec<_, RP_PARAMETER_L>, Error>>()?
            .into_inner()
            .expect("impossible; len will always be RP_PARAMETER_L");

        Ok(RangeProof { digit_proofs })
    }
}

#[allow(unused)]
impl RangeProof {
    /// Verify that the PoKs on the opening of signatures for each digit are valid.
    ///
    /// Return `MessageLengthMismatch` error if the digit proofs are malformed with respect to the
    /// `RangeProofParameters`.
    /// If none are, return a bool indicating whether ALL the signatures are valid.
    fn verify_range_proof_digits(
        &self,
        params: &RangeProofParameters,
        challenge: Challenge,
    ) -> Result<bool, Error> {
        for proof in &self.digit_proofs {
            if !proof.verify_knowledge_of_signature(&params.public_key, challenge)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify that the response scalar for a given value is correctly constructed from the range
    /// proof digits.
    ///
    /// Return `MessageLengthMismatch` error if the proof is malformed with respect to the provided
    /// `RangeProofParameters`.
    /// Otherwise, return a bool indicating whether the digit proofs are valid and are correctly
    /// formed with respect to the given `Scalar`.
    pub fn verify_range_proof(
        &self,
        params: &RangeProofParameters,
        challenge: Challenge,
        expected_response_scalar: Scalar,
    ) -> Result<bool, Error> {
        let valid_digits = self.verify_range_proof_digits(params, challenge)?;

        // Construct cumulative response scalar from the response scalars of the individual digits.
        let mut response_scalar = Scalar::zero();
        // u_pow holds the term u^j for j = 0 .. RP_PARAMETER_L
        let mut u_pow = Scalar::one();
        // sum ( u^j * response_scalar[j] )
        for proof in &self.digit_proofs {
            response_scalar += u_pow * proof.conjunction_response_scalars()[0];
            u_pow *= Scalar::from(RP_PARAMETER_U);
        }

        Ok(valid_digits && response_scalar == expected_response_scalar)
    }
}
