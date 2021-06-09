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
    for the blinding factor. They form a commitment to the commitment scalars. The outputs of steps
    0 and 1 is described by [`SignatureProofBuilder`].

2. *Challenge*. In an interactive proof, the prover obtains a random challenge from the verifier.
    However, it is standard practice to use the Fiat-Shamir heuristic to transform an interactive
    proof into a non-interactive proof; see [`Challenge`] for details.

3. *Response*. The prover constructs response scalars, which mask each element of the message tuple
    and the blinding factor with the corresponding commitment scalar and the challenge.

Note that steps 1-3 are identical to those for a [commitment proof](crate::commitment_proof).
The [`SignatureProof`] consists of the commitment to the commitment scalars; the response scalars;
the blinded, randomized signature; and the commitment to the message tuple from step 0.

Given the proof, the verifier checks the following:
1. The underlying commitment proof is consistent (i.e. with the commitment to commitment scalars,
    the challenge, and the responses scalars).
2. The (blinded, randomized) signature is valid.
3. The signature is consistent with the commitment to the message.

A malicious prover cannot produce a valid, consistent set of objects without knowing the underlying
message.

## References
1: David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor, Topics in
Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International Publishing, Cham, 2016.

i. C. P. Schnorr. Efficient signature generation by smart cards. Journal of Cryptology, 4(3):161–174, Jan 1991.
*/
use crate::{
    challenge::Challenge,
    commitment_proof::{CommitmentProof, CommitmentProofBuilder},
    message::BlindingFactor,
    pedersen_commitments::Commitment,
    ps_blind_signatures::BlindedSignature,
    ps_keys::PublicKey,
    ps_signatures::Signature,
    types::*,
    Error,
};

/// Fully constructed proof of knowledge of a signature.
#[derive(Debug, Clone)]
pub struct SignatureProof<const N: usize> {
    /// Commitment to the signed message.
    pub message_commitment: Commitment<G2Projective>,
    /// Blinded, randomized version of the signature.
    pub blinded_signature: BlindedSignature,
    /// Proof of knowledge of opening of the `message_commitment`.
    pub commitment_proof: CommitmentProof<G2Projective, N>,
}

/**
A partially-built [`SignatureProof`].

Built up to (but not including) the challenge phase of a Schnorr proof.
*/
#[derive(Debug, Clone)]
pub struct SignatureProofBuilder<const N: usize> {
    /// Underlying message in the signature.
    pub message: Message<N>,
    /// Commitment to the message.
    pub message_commitment: Commitment<G2Projective>,
    /// Blinding factor for the `message_commitment`.
    pub message_blinding_factor: BlindingFactor,
    /// Randomized and blinded version of the original signature.
    pub blinded_signature: BlindedSignature,
    /// Commitment phase output for the underlying proof of knowledge of the opening of the `message_commitment`.
    pub commitment_proof_builder: CommitmentProofBuilder<G2Projective, N>,
}

impl<const N: usize> SignatureProofBuilder<N> {
    /**
    Run the commitment phase of a Schnorr-style signature proof.

    The `conjunction_commitment_scalars` argument allows the caller to choose particular commitment
    scalars in the case that they need to satisfy some sort of constraint, for example when
    implementing equality or linear combination constraints on top of the proof.

    Return a `MessageLengthMismatch` error if the provided message or `conjunction_commitment_scalars`
    are malformed with respect to the provided `PublicKey`.
    */
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        message: Message<N>,
        signature: Signature,
        conjunction_commitment_scalars: &[Option<Scalar>],
        params: &PublicKey<N>,
    ) -> Result<Self, Error> {
        // Run commitment phase for PoK of opening of commitment to message.
        let params = params.to_g2_pedersen_parameters();
        let commitment_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            conjunction_commitment_scalars,
            &params,
        )?;

        // Run signature proof setup phase:
        // Blind and randomize signature
        let message_blinding_factor = BlindingFactor::new(rng);
        let mut blinded_signature = BlindedSignature::blind(signature, message_blinding_factor);
        blinded_signature.randomize(rng);

        // Form commitment to blinding factor + message
        let message_commitment = params.commit(&message, message_blinding_factor)?;

        Ok(Self {
            message,
            message_commitment,
            message_blinding_factor,
            blinded_signature,
            commitment_proof_builder,
        })
    }

    /// Get the commitment scalars corresponding to the message tuple to use when constructing
    /// conjunctions of proofs.
    ///
    /// This does not include the commitment scalar corresponding to the blinding factor.
    pub fn conjunction_commitment_scalars(&self) -> &[Scalar; N] {
        &self
            .commitment_proof_builder
            .conjunction_commitment_scalars()
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(
        self,
        challenge_scalar: Challenge,
    ) -> Result<SignatureProof<N>, Error> {
        // Run response phase for PoK of opening of commitment to message
        let commitment_proof = self.commitment_proof_builder.generate_proof_response(
            &self.message,
            self.message_blinding_factor,
            challenge_scalar,
        )?;

        Ok(SignatureProof {
            message_commitment: self.message_commitment,
            blinded_signature: self.blinded_signature,
            commitment_proof,
        })
    }
}

impl<const N: usize> SignatureProof<N> {
    /**
    Check that a [`SignatureProof`] is valid.

    Checks that:

    - the blinded signature is correctly formed (first element is non-identity)
    - the internal commitment proof is valid
    - the commitment proof is formed on the same message as the blinded signature

    Return a `MessageLengthMismatch` error if the proof is malformed with respect to the
    provided `PublicKey`.
    */
    pub fn verify_knowledge_of_signature(
        &self,
        params: &PublicKey<N>,
        challenge: Challenge,
    ) -> Result<bool, Error> {
        // signature is well-formed
        let valid_signature = self.blinded_signature.is_well_formed();

        // commitment proof is valid
        let valid_commitment_proof = self
            .commitment_proof
            .verify_knowledge_of_opening_of_commitment(
                &params.to_g2_pedersen_parameters(),
                self.message_commitment,
                challenge,
            )?;

        // commitment proof matches blinded signature
        let Signature { sigma1, sigma2 } = self.blinded_signature.0;
        let commitment_proof_matches_signature =
            pairing(&sigma1, &(params.x2 + self.message_commitment.0).into())
                == pairing(&sigma2, &params.g2);

        Ok(valid_signature && valid_commitment_proof && commitment_proof_matches_signature)
    }

    /// Get the response scalars corresponding to the message to verify conjunctions of proofs.
    ///
    /// This does not include the response scalar for the blinding factor.
    pub fn conjunction_response_scalars(&self) -> &[Scalar] {
        &self.commitment_proof.conjunction_response_scalars()
    }
}
