/*! Generates a proof of knowledge of the opening of a signature - that is, a proof that one knows the underlying message.

These are Schnorr zero-knowledge proofs that use a commitment and response phase to show
that the prover knows the opening of a signature, without revealing the underlying [`Message`].

## Intuition
This is a Schnorr-style protocol, built off of Pointcheval-Sanders signatures \[1\], a randomizable, blindable signature scheme. 
The proof itself is based on the Schnorr proof of knowledge of the opening of a commitment \[2\], but adds an additional preparation
step to adapt it for signatures.

The protocol has four phases to prove knowledge of a signature.

0. *Setup*. The prover blinds and randomizes the signature and forms a commitment to the underlying message. To link these two items together, 
they use the signature blinding factor as the commitment randomness.

1. *Commit*. The prover chooses a random mask for each block in the message and the blinding factor.
They form a commitment to this randomness.
The outputs of steps 0 and 1 is described by [`SignatureProofBuilder`].

2. *Challenge*. The prover obtains a random challenge. There are several acceptable ways to generate this; see [`Challenge`] for details.

3. *Response*. The prover constructs masked versions of each message block, incorporating the blinding factor and the challenge.

Note that steps 1-3 are identical to those for a [commitment proof](crate::commitment_proof). 
The [`SignatureProof`] consists of the commitment to randomness and the masked responses, plus the blinded, randomized signature and corresponding commitment from step 0.

Given the proof, the verifier checks the following:
1. The underlying commitment proof is consistent (i.e. with the commitment to randomness, the challenge, and the responses).
2. The (blinded, randomized) signature is valid.
3. The signature is consistent with the commitment to the message.

The protocol promises that a malicious prover cannot produce a valid, consistent set of objects without knowing the underlying
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
    ps_blind_signatures::{BlindedSignature, BlindingFactor},
    ps_keys::PublicKey,
    ps_signatures::Signature,
    types::*,
};

/// Fully constructed proof of knowledge of a signed message.
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

    The `maybe_commitment_scalars` argument allows the caller to choose particular commitment
    scalars in the case that they need to satisfy some sort of constraint, for example when
    implementing equality or linear combination constraints on top of the proof.
    */
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        message: Message,
        signature: Signature,
        maybe_commitment_scalars: &[Option<Scalar>],
        params: &PublicKey,
    ) -> Self {
        // Run commitment phase for PoK of opening of commitment to message.
        let params = params.to_g2_pedersen_parameters();
        let commitment_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            maybe_commitment_scalars,
            &params,
        );

        // Run signature proof setup phase:
        // Blind and randomize signature
        let blinding_factor = BlindingFactor::new(rng);
        let mut blinded_signature = BlindedSignature::from_signature(&signature, blinding_factor);
        blinded_signature.randomize(rng);

        // Form commitment to blinding factor + message
        let message_commitment_randomness = CommitmentRandomness(blinding_factor.0);
        let message_commitment = params.commit(&message, message_commitment_randomness);

        Self {
            message,
            message_commitment,
            message_commitment_randomness,
            blinded_signature,
            commitment_proof_builder,
        }
    }

    /// Executes the response phase of a Schnorr-style signature proof to complete the proof.
    pub fn generate_proof_response(self, challenge_scalar: Challenge) -> SignatureProof {
        // Run response phase for PoK of opening of commitment to message
        let commitment_proof = self.commitment_proof_builder.generate_proof_response(
            &self.message,
            self.message_commitment_randomness,
            challenge_scalar,
        );

        SignatureProof {
            message_commitment: self.message_commitment,
            blinded_signature: self.blinded_signature,
            commitment_proof,
        }
    }
}
