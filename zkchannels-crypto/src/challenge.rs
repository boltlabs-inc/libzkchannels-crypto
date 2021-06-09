/*!
Functionality for building challenge scalars.

Supports challenges on proofs of knowledge of the opening of commitments, the opening of signatures,
and range proofs, both individually and in conjunctions. There is also support for incorporating
other public information into the challenge.

*/

use crate::{
    pedersen_commitments::{Commitment, PedersenParameters},
    ps_blind_signatures::{BlindedMessage, BlindedSignature},
    ps_keys::PublicKey,
    ps_signatures::Signature,
    range_proof::{RangeProof, RangeProofBuilder},
    signature_proof::{SignatureProof, SignatureProofBuilder},
    types::*,
};
use group::{Group, GroupEncoding};
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;

/// A challenge scalar for use in a Schnorr-style proof.
#[derive(Debug, Clone, Copy)]
pub struct Challenge(Scalar);

impl Challenge {
    /// Converts a `Challenge` to its `Scalar` representation.
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }
}

/// Holds state used when building a [`Challenge`] using the Fiat-Shamir heuristic, as in a
/// non-interactive Schnorr proof.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct ChallengeBuilder {
    hasher: Sha3_256,
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
            hasher: Sha3_256::new(),
        }
    }

    /// Incorporate a commitment into the challenge.
    pub fn with_commitment<G>(self, com: Commitment<G>) -> Self
    where
        G: Group<Scalar = Scalar> + GroupEncoding,
    {
        self.with_bytes(com.0.to_bytes())
    }

    /// Incorporate a blinded message into the challenge.
    pub fn with_blinded_message(self, blinded_message: BlindedMessage) -> Self {
        self.with_commitment(blinded_message.0)
    }

    /// Incorporate public pieces of the [`SignatureProofBuilder`] into the challenge
    /// (e.g. the pieces that will also be in the finalized
    /// [`SignatureProof`](crate::signature_proof::SignatureProof)).
    pub fn with_signature_proof_builder(
        self,
        signature_proof_builder: &SignatureProofBuilder,
    ) -> Self {
        self.with_commitment(signature_proof_builder.message_commitment)
            .with_blinded_signature(&signature_proof_builder.blinded_signature)
            .with_commitment(
                signature_proof_builder
                    .commitment_proof_builder
                    .scalar_commitment,
            )
    }

    /// Incorporate a [`SignatureProof`] into the challenge.
    pub fn with_signature_proof(self, proof: &SignatureProof) -> Self {
        self.with_commitment(proof.message_commitment)
            .with_blinded_signature(&proof.blinded_signature)
            .with_commitment(proof.commitment_proof.scalar_commitment)
    }

    /// Incorporate a [`Signature`] into the challenge.
    pub fn with_signature(self, signature: &Signature) -> Self {
        self.with_bytes(&signature.to_bytes())
    }

    /// Incorporate a [`BlindedSignature`] into the challenge.
    pub fn with_blinded_signature(self, signature: &BlindedSignature) -> Self {
        self.with_bytes(&signature.to_bytes())
    }

    /// Incorporate public pieces of the [`RangeProofBuilder`] into the challenge.
    /// (e.g. the pieces that will also be in the finalized
    /// [`RangeProof`](crate::range_proof::RangeProof)).
    pub fn with_range_proof_builder(self, range_proof_builder: &RangeProofBuilder) -> Self {
        range_proof_builder
            .digit_proof_builders
            .iter()
            .fold(self, |this, proof| this.with_signature_proof_builder(proof))
    }

    /// Incorporate pieces of the [`RangeProof`] into the challenge.
    pub fn with_range_proof(self, range_proof: &RangeProof) -> Self {
        range_proof
            .digit_proofs
            .iter()
            .fold(self, |this, proof| this.with_signature_proof(proof))
    }

    /// Incorporate public key material into the challenge.
    pub fn with_public_key(mut self, pk: &PublicKey) -> Self {
        self = self
            .with_bytes(pk.g1.to_bytes())
            .with_bytes(pk.g2.to_bytes())
            .with_bytes(pk.x2.to_bytes());
        self = pk
            .y1s
            .iter()
            .fold(self, |this, y1| this.with_bytes(y1.to_bytes()));
        self = pk
            .y2s
            .iter()
            .fold(self, |this, y2| this.with_bytes(y2.to_bytes()));
        self
    }

    /// Incorporate Pedersen parameter key material into the challenge.
    pub fn with_pedersen_parameters<G>(self, params: &PedersenParameters<G>) -> Self
    where
        G: Group<Scalar = Scalar> + GroupEncoding,
    {
        params
            .gs
            .iter()
            .fold(self.with_bytes(params.h.to_bytes()), |this, g| {
                this.with_bytes(g.to_bytes())
            })
    }

    /// Incorporate a [`Scalar`] into the challenge (that is, an element of the scalar fields
    /// associated with the BLS12-381 pairing groups)
    pub fn with_scalar(self, scalar: Scalar) -> Self {
        self.with_bytes(scalar.to_bytes())
    }

    /// Incorporate arbitrary bytes into the challenge.
    pub fn with_bytes(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.hasher.update(bytes);
        self
    }

    /// Consume the builder and generate a [`Challenge`] from the accumulated data.
    pub fn finish(self) -> Challenge {
        let mut digested = [0; 32];
        digested.copy_from_slice(self.hasher.finalize().as_ref());
        let scalar = Scalar::from_raw([
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&digested[24..32]).unwrap()),
        ]);
        Challenge(scalar)
    }
}
