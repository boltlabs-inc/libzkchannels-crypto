//! Pedersen commitments \[1\] over the prime-order pairing groups from BLS12-381 \[2\].
//!
//! Commitments may be formed using the [`PedersenParameters`] struct's [`commit`] and [`decommit`]
//! methods. [`PedersenParameters`] may be constructed by uniform random sampling from an [`Rng`],
//! using the [`PedersenParameters::new`] method.
//! ```
//! # use zkchannels_crypto::{BlindingFactor, Message, pedersen::PedersenParameters};
//! # use bls12_381::G1Projective;
//! # let mut rng = rand::thread_rng();
//! let params = PedersenParameters::<G1Projective, 5>::new(&mut rng);
//! let msg = Message::<5>::random(&mut rng);
//! let bf = BlindingFactor::new(&mut rng);
//! let commitment = params.commit(&msg, bf);
//! assert!(params.decommit(&msg, bf, commitment));
//! ```
//!
//! ## References
//!
//! 1. Torben Pyrds Pedersen. "Non-interactive and information-theoretic secure verifiable secret
//!    sharing". 1992. URL: <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>
//!
//! 2. D. Boneh, S. Gorbunov, R. Wahby, H. Wee, and Z. Zhang. "BLS Signatures, Version 4".
//!    Internet-draft, IETF. 2021. URL:
//!    <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04>
//!
//! [`commit`]: PedersenParameters::commit
//! [`decommit`]: PedersenParameters::decommit
//! [`Rng`]: crate::Rng

use crate::{
    common::*,
    proofs::{ChallengeBuilder, ChallengeInput},
    serde::{SerializeElement, SerializeG1},
};
use arrayvec::ArrayVec;
use group::Group;
use serde::{Deserialize, Serialize};
use std::iter;

/// A Pedersen commitment to a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound = "G: SerializeElement")]
pub struct Commitment<G>(#[serde(with = "SerializeElement")] G)
where
    G: Group<Scalar = Scalar>;

impl<G: Group<Scalar = Scalar>> Commitment<G> {
    /// Get the inner group element representing the commitment.
    pub fn to_element(self) -> G {
        self.0
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding> ChallengeInput for Commitment<G> {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.to_element().to_bytes());
    }
}

/// Parameters for Pedersen commitments.
///
/// These are defined over the prime-order pairing groups from BLS12-381.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "G: SerializeG1")]
pub struct PedersenParameters<G, const N: usize>
where
    G: Group<Scalar = Scalar>,
{
    #[serde(with = "SerializeElement")]
    pub(crate) h: G,
    #[serde(with = "SerializeElement")]
    pub(crate) gs: [G; N],
}

#[cfg(feature = "sqlite")]
crate::impl_sqlx_for_bincode_ty!(PedersenParameters<G1Projective, 1>);

impl<G: Group<Scalar = Scalar>, const N: usize> PedersenParameters<G, N> {
    /// Generate a new set of parameters for making commitments to messages of given
    /// length.
    ///
    /// These are chosen uniformly at random, such that no discrete logarithm relationships
    /// are known among the generators.
    pub fn new(rng: &mut impl Rng) -> Self {
        let h: G = random_non_identity(&mut *rng);
        let gs = iter::repeat_with(|| random_non_identity(&mut *rng))
            .take(N)
            .collect::<ArrayVec<_, N>>()
            .into_inner()
            .expect("length mismatch impossible");
        Self { h, gs }
    }

    /// Commit to a message using the provided blinding factor.
    pub fn commit(&self, msg: &Message<N>, bf: BlindingFactor) -> Commitment<G> {
        let com: G = self.h * bf.to_scalar()
            + self
                .gs
                .iter()
                .zip(msg.iter())
                .map(|(&g, m)| g * m)
                .sum::<G>();

        Commitment(com)
    }

    /// Verify a commitment to a message, using the given blinding factor.
    pub fn decommit(&self, msg: &Message<N>, bf: BlindingFactor, com: Commitment<G>) -> bool {
        self.commit(msg, bf) == com
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeInput
    for PedersenParameters<G, N>
{
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.h.to_bytes());
        for g in &self.gs {
            builder.consume_bytes(g.to_bytes());
        }
    }
}
