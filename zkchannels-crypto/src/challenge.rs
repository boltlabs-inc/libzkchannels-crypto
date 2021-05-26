/*!
Functionality for building challenge scalars.

Supports challenges on proofs of knowledge of the opening of commitments, the opening of signatures,
and range proofs, both individually and in conjunctions. There is also support for incorporating
other public information into the challenge.

*/

use crate::{
    commitment_proof::CommitmentProofBuilder,
    pedersen_commitments::{Commitment, PedersenParameters},
    ps_keys::PublicKey,
    range_proof::RangeProofBuilder,
    signature_proof::SignatureProofBuilder,
    types::*,
};
use group::{Group, GroupEncoding};
use sha3::{Digest, Sha3_512};

/// A challenge scalar for use in a Schnorr-style proof.
#[derive(Debug, Clone, Copy)]
pub struct Challenge(pub Scalar);

/// Holds state used when building a [`Challenge`] using the Fiat-Shamir heuristic, as in a
/// non-interactive Schnorr proof.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
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

    /// Incorporate a commitment into the challenge.
    pub fn with_commitment<G>(self, _com: &Commitment<G>) -> Self
    where
        G: Group<Scalar = Scalar> + GroupEncoding,
    {
        todo!();
    }

    /// Incorporate public pieces of the [`CommitmentProofBuilder`] into the challenge
    ///
    /// (e.g. the pieces that will also be in the finalized
    /// [`CommitmentProof`](crate::commitment_proof::CommitmentProof)).
    pub fn with_commitment_proof<G>(self, com: &CommitmentProofBuilder<G>) -> Self
    where
        G: Group<Scalar = Scalar> + GroupEncoding,
    {
        self.with_bytes(com.scalar_commitment.0.to_bytes())
    }

    /// Incorporate public pieces of the [`SignatureProofBuilder`] into the challenge
    /// (e.g. the pieces that will also be in the finalized
    /// [`SignatureProof`](crate::signature_proof::SignatureProof)).
    pub fn with_signature_proof(self, signature_proof_builder: SignatureProofBuilder) -> Self {
        self.with_bytes(signature_proof_builder.message_commitment.0.to_bytes())
            .with_bytes(signature_proof_builder.blinded_signature.to_bytes())
            .with_commitment_proof(&signature_proof_builder.commitment_proof_builder)
    }

    /// Incorporate public pieces of the [`RangeProofBuilder`] into the challenge.
    /// (e.g. the pieces that will also be in the finalized
    /// [`RangeProof`](crate::range_proof::RangeProof)).
    pub fn with_range_proof(self, _range_proof_builder: RangeProofBuilder) -> Self {
        todo!();
    }

    /// Incorporate public key material into the challenge.
    pub fn with_public_key(self, _public_key: &PublicKey) -> Self {
        todo!();
    }

    /// Incorporate Pedersen parameter key material into the challenge.
    pub fn with_pedersen_parameters<G>(self, _params: &PedersenParameters<G>) -> Self
    where
        G: Group<Scalar = Scalar>,
    {
        todo!();
    }

    /// Incorporate a [`Scalar`] into the challenge (that is, an element of the scalar fields
    /// associated with the BLS12-381 pairing groups)
    pub fn with_scalar(self, _scalar: Scalar) -> Self {
        todo!();
    }

    /// Incorporate arbitrary bytes into the challenge.
    pub fn with_bytes(self, _bytes: impl AsRef<[u8]>) -> Self {
        todo!();
    }

    /// Consume the builder and generate a [`Challenge`] from the accumulated data.
    pub fn finish(self) -> Challenge {
        let mut digested = [0; 64];
        digested.copy_from_slice(self.hasher.finalize().as_ref());
        let scalar = Scalar::from_bytes_wide(&digested);
        Challenge(scalar)
    }
}
