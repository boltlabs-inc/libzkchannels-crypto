/*!
Schnorr-style proofs of knowledge that a value lies within the range `[0, 2^63)`.

**This range proof cannot be used alone!** It is only meaningful when used in conjunction with a
[`CommitmentProof`](crate::commitment_proof::CommitmentProof) or [`SignatureProof`], to show that
the message _in that proof_ lies within the given range.

These are Camenish, Chaabouni, and shelat-style range proofs \[1\] built using standard Schnorr.
They prove a value is in range `[0, u^l)`, for some parameters `u` and `l`. This implementation
selects `u`, `l` to produce proofs for the range `[0, 2^63)`
It also uses single-message Pointcheval-Sanders signatures \[2\] instead of the signature scheme
in \[1\]. It uses the pairing group defined in BLS12-381 \[3\].

## Intuition
The general technique writes the value in `u`-ary digits. That is, a value `B` has digits
`B0 .. Bl`, where each `Bi` is in the range `[0,u)`. The digits componse to `B`; that is, they
have the property `B = sum( u^i * Bi )`.

The prover shows they know the opening of signatures on each of these digits, and that the digits
compose into the original value. The signatures of each possible digit are provided by the
verifier, who uses a special range proof key to sign the values 0 to `u` and publishes them.

This module provides tools to produce a PoK over the digit signatures for a given value. However,
it alone *does not* show that the digits compose into a meaningful value! This step requires a
conjunction with a [`CommitmentProof`](crate::commitment_proof::CommitmentProof) or
[`SignatureProof`].

Of course, this special structure requires additional parameters and a more computationally
intensive setup phase by the verifier. Luckily, this only has to be done once over the lifetime of
_all_ range proofs. It is important that the verifier does not reuse the range proof key for any
other operations, especially signing operations: the security of the proof depends on the fact
that the digit signatures can _only_ be on valid `u`-nary digits.

## Expected use
Suppose you wish to show that the `j`th message element in a
[`CommitmentProof`](crate::commitment_proof::CommitmentProof) is within the range.

1. *Initiate the range proof.*
Call [`RangeProofBuilder::generate_proof_commitments()`], passing the value you wish to show is
in a range.

2. *Link to the commitment proof*.
    The resulting [`RangeProofBuilder`] contains a field called `commitment_scalar`. Place this
    element in the `j`th index of `known_commitment_scalars` and use it to [generate the 
    CommitmentProof` commitments](crate::commitment_proof::CommitmentProofBuilder::generate_proof_commitments()).

3. *Generate a challenge*. In an interactive proof, the prover obtains a random challenge from the
    verifier. However, it is standard practice to use the Fiat-Shamir heuristic to transform an 
    interactive proof into a non-interactive proof; see [`Challenge`] for details.

4. *Complete the proofs*.
    Call the `generate_proof_response()` function for the
    [commitment proof](crate::commitment_proof::CommitmentProofBuilder::generate_proof_response())
    and the [range proof](RangeProofBuilder::generate_proof_response()).

To verify a range proof, the verifier must check the following:

1. The commitment proof is correctly constructed.
2. The range proof digits are correctly constructed.
3. The value in the commitment proof corresponds to the digits in the range proof.

To do so, the verifier should first reconstruct the challenge.
Verify 1 using the standard commitment proof
[verification function](crate::commitment_proof::CommitmentProof::verify_knowledge_of_opening_of_commitment()).
To verify 2 and 3, retrieve the `j`th response scalar using
[`CommitmentProof::response_scalars()`](crate::commitment_proof::CommitmentProof::response_scalars())
and pass it to [`verify_range_proof()`](RangeProof::verify_range_proof())

The approach for a signature proof is similar.

## References

1: Jan Camenisch, Rafik Chaabouni, and abhi shelat. Efficient protocols for set membership and range proofs.
In Josef Pieprzyk, editor, Advances in Cryptology - ASIACRYPT 2008, pages 234–252, Berlin, Heidelberg,
2008. Springer Berlin Heidelberg.

2: David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor, Topics in
Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International Publishing, Cham, 2016.

3: Dan Boneh, Sergey Gorbunov, Riad S. Wahby, Hoeteck Wee, and Zhenfei Zhang. BLS Signatures, revision 4.
Internet draft, Internet Engineering Task Force, 2020.
https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04

*/

use crate::{
    challenge::Challenge, ps_keys::PublicKey, ps_signatures::Signature, signature_proof::*,
};
use crate::{types::*, Error};

/// The arity of our digits used in the range proof.
const RP_PARAMETER_U: u64 = 128;

/// Number of digits used in the range proof.
const RP_PARAMETER_L: usize = 7;

/// Parameters for use in a [`RangeProof`].
///
/// These should be generated by a trusted party (e.g. the verifier) and can be shared with any potential provers.
#[allow(unused)]
#[derive(Debug)]
pub struct RangeProofParameters {
    /// A signature on every `u`-nary digit
    digit_signatures: [Signature; RP_PARAMETER_U as usize],
    /// Public key corresponding _exclusively with the signatures above.
    public_key: PublicKey,
}

impl RangeProofParameters {
    /**
    Generate new parameters for use in range proofs.

    Note that this generates a [`KeyPair`](crate::ps_keys::KeyPair) to produce the `digit_signatures`,
    but discards the secret half after use. This is to prevent misuse; it should never be used again.
    */
    pub fn new(_rng: &mut impl Rng) -> Self {
        todo!();
    }
}

/// A partially-built [`RangeProof`].
///
/// It contains the output of the PoK of signatures setup phase and the Schnorr commitment phase.
#[allow(unused)]
#[derive(Debug)]
pub struct RangeProofBuilder {
    /// Partially-constructed PoK of the opening of signatures on each of the digits of the value.
    digit_proof_builders: [SignatureProofBuilder; RP_PARAMETER_L],
    /// Commitment scalar for the value being proven in the range.
    pub commitment_scalar: Scalar,
}

/// Proof of knowledge of a set of digits that compose a value within the range. This is **not** a complete range proof
/// unless supplied in conjunction with a [`CommitmentProof`](crate::commitment_proof::CommitmentProof) or a [`SignatureProof`].
#[allow(unused)]
#[derive(Debug)]
pub struct RangeProof {
    /// Complete PoKs of the opening of a signature on each digit of the value.
    pub digit_proofs: [SignatureProof; RP_PARAMETER_L],
}

#[allow(unused)]
impl RangeProofBuilder {
    /// Run the commitment phase of a Schnorr-style range proof on the value n, to show that `0 < n < u^l`.
    pub fn generate_proof_commitments(
        _n: i64,
        _params: &RangeProofParameters,
        _rng: &mut impl Rng,
    ) -> Result<Self, Error> {
        todo!();
    }

    /// Run the response phase of a Schnorr-style proof of knowledge that a value is in a range.
    pub fn generate_proof_response(self, challenge: Challenge) -> RangeProof {
        todo!();
    }
}

#[allow(unused)]
impl RangeProof {
    /// Verify that the PoKs on the opening of signatures for each digit are valid.
    fn verify_range_proof_digits(
        &self,
        _params: &RangeProofParameters,
        _challenge: Challenge,
    ) -> bool {
        todo!();
    }

    /// Verify that the response scalar for a given value is correctly constructed from the range proof digits.
    pub fn verify_range_proof(
        &self,
        _params: &RangeProofParameters,
        _challenge: Challenge,
        _expected_response_scalar: Scalar,
    ) -> bool {
        todo!();
    }
}
