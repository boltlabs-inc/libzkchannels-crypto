//! Functionality for building challenge scalars.

use crate::{
    pedersen_commitments::CommitmentProofBuilder, signature_proof::SignatureProofBuilder, types::*,
};
use group::{Group, GroupEncoding};
use sha3::{Digest, Sha3_512};

/// A challenge scalar for use in a Schnorr-style proof
#[derive(Debug, Clone, Copy)]
pub struct ChallengeScalar(pub Scalar);

/// Holds state used when building a [`ChallengeScalar`] by hashing, as in a non-interactive Schnorr
/// proof.
#[derive(Debug)]
pub struct ChallengeBuilder {
    hasher: Sha3_512,
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeBuilder {
    /// Initialize a new, empty challenge.
    pub fn new() -> Self {
        Self {
            hasher: Sha3_512::new(),
        }
    }

    /// Incorporate public pieces of the [`CommitmentProofBuilder`] into the challenge.
    pub fn with_commitment_proof<G>(self, com: &CommitmentProofBuilder<G>) -> Self
    where
        G: Group<Scalar = Scalar> + GroupEncoding,
    {
        self.with_bytes(com.scalar_commitment.0.to_bytes())
    }

    /// Incorporate public pieces of the [`SignatureProofBuilder`] into the challenge.
    pub fn with_signature_proof(self, signature_proof_builder: SignatureProofBuilder) -> Self {
        self.with_bytes(signature_proof_builder.message_commitment.0.to_bytes())
            .with_bytes(signature_proof_builder.blinded_signature.to_bytes())
            .with_commitment_proof(&signature_proof_builder.commitment_proof_builder)
    }

    /// Incorporate arbitrary bytes into the challenge.
    pub fn with_bytes(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.hasher.update(bytes);
        self
    }

    /// Consume the builder and generate a [`ChallengeScalar`] from the accumulated data.
    pub fn finish(self) -> ChallengeScalar {
        let mut digested = [0; 64];
        digested.copy_from_slice(self.hasher.finalize().as_ref());
        let scalar = Scalar::from_bytes_wide(&digested);
        ChallengeScalar(scalar)
    }
}
