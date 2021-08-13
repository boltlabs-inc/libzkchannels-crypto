//! Proofs of knowledge of a signature - that is, a proof that one knows the underlying message.
//!
//! These are Schnorr zero-knowledge proofs that use a commitment and response phase to show that
//! the prover knows the opening of a signature, without revealing the underlying [`Message`].
//!
//! ## Intuition
//! This is a Schnorr-style implementation of the efficient protocol from Pointcheval-Sanders \[1\],
//! which defines a randomizable, blindable signature scheme. The proof itself is based on the
//! Schnorr proof of knowledge of the opening of a commitment \[2\], but adds an additional
//! preparation step to adapt it for signatures.
//!
//! The protocol has four phases to prove knowledge of a signature.
//!
//! 0. *Setup*. The prover blinds and randomizes the signature and forms a commitment to the
//!     underlying message. They use the same blinding factor to blind the signature and to form the
//!     commitment.
//!
//! 1. *Commit*. The prover chooses random commitment scalars for each element in the message tuple
//!     and for the blinding factor. They form a commitment to the commitment scalars. The outputs
//!     of steps 0 and 1 is described by [`SignatureProofBuilder`].
//!
//! 2. *Challenge*. In an interactive proof, the prover obtains a random challenge from the
//!     verifier. However, it is standard practice to use the Fiat-Shamir heuristic to transform an
//!     interactive proof into a non-interactive proof; see [`Challenge`] for details.
//!
//! 3. *Response*. The prover constructs response scalars, which mask each element of the message
//!     tuple and the blinding factor with the corresponding commitment scalar and the challenge.
//!
//! Note that steps 1-3 are identical to those for a [commitment
//! proof](crate::proofs::CommitmentProof). The [`SignatureProof`] consists of the commitment to the
//! commitment scalars; the response scalars; the blinded, randomized signature; and the commitment
//! to the message tuple from step 0.
//!
//! Given the proof, the verifier checks the following:
//! 1. The underlying commitment proof is consistent (i.e. with the commitment to commitment
//!     scalars, the challenge, and the responses scalars).
//! 2. The (blinded, randomized) signature is valid.
//! 3. The signature is consistent with the commitment to the message.
//!
//! A malicious prover cannot produce a valid, consistent set of objects without knowing the
//! underlying message.
//!
//! ## References
//! 1. David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor,
//!    Topics in Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International
//!    Publishing, Cham, 2016.
//!
//! 2. C. P. Schnorr. Efficient signature generation by smart cards. Journal of Cryptology,
//!    4(3):161–174, Jan 1991.

use crate::{
    common::*,
    pedersen::PedersenParameters,
    pointcheval_sanders::{BlindedSignature, PublicKey, Signature},
    proofs::{
        Challenge, ChallengeBuilder, ChallengeInput, CommitmentProof, CommitmentProofBuilder,
    },
};
use serde::{Deserialize, Serialize};

/// Fully constructed proof of knowledge of a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureProof<const N: usize> {
    /// Blinded, randomized version of the signature.
    blinded_signature: BlindedSignature,
    /// Proof of knowledge of opening of the `message_commitment`.
    commitment_proof: CommitmentProof<G2Projective, N>,
}

/// A partially-built [`SignatureProof`].
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct SignatureProofBuilder<const N: usize> {
    /// Randomized and blinded version of the original signature.
    blinded_signature: BlindedSignature,
    /// Commitment phase output for the underlying proof of knowledge of the opening of the `message_commitment`.
    commitment_proof_builder: CommitmentProofBuilder<G2Projective, N>,
}

impl<const N: usize> SignatureProofBuilder<N> {
    /// Run the commitment phase of a Schnorr-style signature proof.
    ///
    /// The `conjunction_commitment_scalars` argument allows the caller to choose particular
    /// commitment scalars in the case that they need to satisfy some sort of constraint, for
    /// example when implementing equality or linear combination constraints on top of the proof.
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        message: Message<N>,
        signature: Signature,
        conjunction_commitment_scalars: &[Option<Scalar>; N],
        params: &PublicKey<N>,
    ) -> Self {
        // Run commitment phase for PoK of opening of commitment to message.
        let pedersen_params = PedersenParameters::<G2Projective, N>::from_public_key(params);

        // Run signature proof setup phase:
        // Form commitment to blinding factor + message
        let commitment_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            message,
            conjunction_commitment_scalars,
            &pedersen_params,
        );

        // Blind and randomize signature
        let mut blinded_signature = BlindedSignature::blind(
            signature,
            commitment_proof_builder.message_blinding_factor(),
        );
        blinded_signature.randomize(rng);

        Self {
            blinded_signature,
            commitment_proof_builder,
        }
    }

    /// Get the commitment scalars corresponding to the message tuple to use when constructing
    /// conjunctions of proofs.
    ///
    /// This does not include the commitment scalar corresponding to the blinding factor.
    pub fn conjunction_commitment_scalars(&self) -> &[Scalar; N] {
        self.commitment_proof_builder
            .conjunction_commitment_scalars()
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(self, challenge_scalar: Challenge) -> SignatureProof<N> {
        // Run response phase for PoK of opening of commitment to message
        let commitment_proof = self
            .commitment_proof_builder
            .generate_proof_response(challenge_scalar);

        SignatureProof {
            blinded_signature: self.blinded_signature,
            commitment_proof,
        }
    }
}

impl<const N: usize> ChallengeInput for SignatureProofBuilder<N> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.blinded_signature);
        builder.consume(&self.commitment_proof_builder);
    }
}

impl<const N: usize> SignatureProof<N> {
    /// Check that a [`SignatureProof`] is valid.
    ///
    /// Checks that:
    ///
    /// - the blinded signature is correctly formed (first element is non-identity)
    /// - the internal commitment proof is valid
    /// - the commitment proof is formed on the same message as the blinded signature
    pub fn verify_knowledge_of_signature(
        &self,
        params: &PublicKey<N>,
        challenge: Challenge,
    ) -> bool {
        // signature is well-formed
        let valid_signature = self.blinded_signature.is_well_formed();

        // commitment proof is valid
        let valid_commitment_proof = self
            .commitment_proof
            .verify_knowledge_of_opening_of_commitment(
                &PedersenParameters::<G2Projective, N>::from_public_key(params),
                challenge,
            );

        // commitment proof matches blinded signature
        let commitment_proof_matches_signature =
            pairing(
                &self.blinded_signature.sigma1(),
                &(params.x2 + self.commitment_proof.commitment().to_element()).into(),
            ) == pairing(&self.blinded_signature.sigma2(), &params.g2);

        valid_signature && valid_commitment_proof && commitment_proof_matches_signature
    }

    /// Get the response scalars corresponding to the message to verify conjunctions of proofs.
    ///
    /// This does not include the response scalar for the blinding factor.
    pub fn conjunction_response_scalars(&self) -> &[Scalar; N] {
        self.commitment_proof.conjunction_response_scalars()
    }
}

impl<const N: usize> ChallengeInput for SignatureProof<N> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.blinded_signature);
        builder.consume(&self.commitment_proof);
    }
}
