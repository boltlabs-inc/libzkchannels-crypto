/*!
Proofs of knowledge of a signature - that is, a proof that one knows the
underlying message.

These are Schnorr zero-knowledge proofs that use a commitment and response phase to show
that the prover knows the opening of a signature, without revealing the underlying [`Message`].

## Intuition
This is a Schnorr-style implementation of the efficient protocol from Pointcheval-Sanders \[1\],
which defines a randomizable, blindable signature scheme. The proof itself is based on the Schnorr
proof of knowledge of the opening of a commitment \[2\], but adds an additional preparation step
to adapt it for signatures.

The protocol has four phases to prove knowledge of a signature.

0. *Setup*. The prover blinds and randomizes the signature and forms a commitment to the underlying
    message. They use the same blinding factor to blind the signature and to form the commitment.

1. *Commit*. The prover chooses random commitment scalars for each element in the message tuple and
    for the blinding factor. They form a commitment to this randomness. The outputs of steps 0 and
    1 is described by [`SignatureProofBuilder`].

2. *Challenge*. In an interactive proof, the prover obtains a random challenge from the verifier.
    However, it is standard practice to use the Fiat-Shamir heuristic to transform an interactive
    proof into a non-interactive proof; see [`Challenge`] for details.

3. *Response*. The prover constructs response scalars, which mask each element of the message tuple
    and the blinding factor with the corresponding commitment scalar and the challenge.

Note that steps 1-3 are identical to those for a [commitment proof](crate::commitment_proof).
The [`SignatureProof`] consists of the commitment to the commitment scalars; the response scalars; 
the blinded, randomized signature; and the commitment to the message tuple from step 0.

Given the proof, the verifier checks the following:
1. The underlying commitment proof is consistent (i.e. with the commitment to randomness, the
    challenge, and the responses).
2. The (blinded, randomized) signature is valid.
3. The signature is consistent with the commitment to the message.

A malicious prover cannot produce a valid, consistent set of objects without knowing the underlying
message.

## References
1: David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor, Topics in
Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International Publishing, Cham, 2016.

2. C. P. Schnorr. Efficient signature generation by smart cards. Journal of Cryptology, 4(3):161–174, Jan 1991.
*/
use crate::{
    challenge::Challenge,
    commitment_proof::{CommitmentProof, CommitmentProofBuilder},
    pedersen_commitments::{Commitment, CommitmentRandomness},
    ps_blind_signatures::BlindedSignature,
    ps_keys::PublicKey,
    ps_signatures::Signature,
    types::*,
};

/// Fully constructed proof of knowledge of a signature.
#[derive(Debug, Clone)]
pub struct SignatureProof {
    /// Commitment to the signed message.
    pub message_commitment: Commitment<G2Projective>,
    /// Blinded, randomized version of the signature.
    pub blinded_signature: BlindedSignature,
    /// Proof of knowledge of opening of the `message_commitment`.
    pub commitment_proof: CommitmentProof<G2Projective>,
}

/**
A partially-built [`SignatureProof`].

Built up to (but not including) the challenge phase of a Schnorr proof.
*/
#[derive(Debug, Clone)]
pub struct SignatureProofBuilder {
    /// Underlying message in the signature.
    pub message: Message,
    /// Commitment to the message.
    pub message_commitment: Commitment<G2Projective>,
    /// Commitment randomness corresponding to the `message_commitment`.
    pub message_commitment_randomness: CommitmentRandomness,
    /// Randomized and blinded version of the original signature.
    pub blinded_signature: BlindedSignature,
    /// Commitment phase output for the underlying proof of knowledge of the opening of the `message_commitment`.
    pub commitment_proof_builder: CommitmentProofBuilder<G2Projective>,
}

impl SignatureProofBuilder {
    /**
    Run the commitment phase of a Schnorr-style signature proof.

    The `conjunction_commitment_scalars` argument allows the caller to choose particular commitment
    scalars in the case that they need to satisfy some sort of constraint, for example when
    implementing equality or linear combination constraints on top of the proof.
    */
    pub fn generate_proof_commitments(
        _rng: &mut impl Rng,
        _message: Message,
        _signature: Signature,
        _conjunction_commitment_scalars: &[Option<Scalar>],
        _params: &PublicKey,
    ) -> Self {
        todo!();
    }

    /// Get the commitment scalars corresponding to the message for the signature proof being 
    /// built (e.g. not including the commitment scalar corresponding to the blinding factor).
    pub fn commitment_scalars(&self) -> &[Scalar] {
        &self.commitment_proof_builder.commitment_scalars()
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(self, _challenge: Challenge) -> SignatureProof {
        todo!();
    }
}

impl SignatureProof {
    /**
    Checks that a [`SignatureProof`] is valid.

    Checks that:

    - the blinded signature is correctly formed (first element is non-identity)
    - the internal commitment proof is valid
    - the commitment proof is formed on the same message as the blinded signature
    */
    pub fn verify_knowledge_of_opening_of_signature(
        &self,
        _params: &PublicKey,
        _challenge: Challenge,
    ) -> bool {
        todo!();
    }

    /// Retrieves the response scalars for the signature proof, not including the response scalar
    /// corresponding to the blinding factor.
    pub fn response_scalars(&self) -> &[Scalar] {
        &self.commitment_proof.response_scalars()
    }
}
