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
    proofs::{ChallengeBuilder, ChallengeDigest},
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

impl<G: Group<Scalar = Scalar> + GroupEncoding> ChallengeDigest for Commitment<G> {
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.to_element().to_bytes());
    }
}

/// Parameters for Pedersen commitments.
///
/// These are defined over the prime-order pairing groups from BLS12-381.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeDigest
    for PedersenParameters<G, N>
{
    fn digest(&self, builder: &mut ChallengeBuilder) {
        builder.digest_bytes(self.h.to_bytes());
        for g in &self.gs {
            builder.digest_bytes(g.to_bytes());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn commit_decommit<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let com = params.commit(&msg, bf);
        assert!(params.decommit(&msg, bf, com));
    }

    #[test]
    fn commit_decommit_g1() {
        commit_decommit::<G1Projective>()
    }

    #[test]
    fn commit_decommit_g2() {
        commit_decommit::<G2Projective>()
    }

    fn commit_does_not_decommit_on_wrong_msg<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let bad_msg = Message::random(&mut rng);

        assert_ne!(&*msg, &*bad_msg, "unfortunate RNG seed: bad_msg should be different");

        let com = params.commit(&msg, bf);
        assert!(!params.decommit(&bad_msg, bf, com));
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_msg_g1() {
        commit_does_not_decommit_on_wrong_msg::<G1Projective>()
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_msg_g2() {
        commit_does_not_decommit_on_wrong_msg::<G2Projective>()
    }

    fn commit_does_not_decommit_on_wrong_bf<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);
        let bad_bf = BlindingFactor::new(&mut rng);

        assert_ne!(bf.0, bad_bf.0, "unfortunate RNG seed: bad_bf should be different");

        let com = params.commit(&msg, bf);
        assert!(!params.decommit(&msg, bad_bf, com));
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_bf_g1() {
        commit_does_not_decommit_on_wrong_bf::<G1Projective>()
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_bf_g2() {
        commit_does_not_decommit_on_wrong_bf::<G2Projective>()
    }

    fn commit_does_not_decommit_on_wrong_commit<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let bad_com = {
            let msg = Message::random(&mut rng);
            params.commit(&msg, bf)
        };

        let com = params.commit(&msg, bf);

        assert_ne!(com.0, bad_com.0, "unfortunate RNG seed: bad_com should be different");
        assert!(!params.decommit(&msg, bf, bad_com));
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_commit_g1() {
        commit_does_not_decommit_on_wrong_commit::<G1Projective>()
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_commit_g2() {
        commit_does_not_decommit_on_wrong_commit::<G2Projective>()
    }

    fn commit_does_not_decommit_on_random_commit<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let bad_com = Commitment::<G>(G::random(&mut rng));

        let com = params.commit(&msg, bf);

        assert_ne!(com.0, bad_com.0, "unfortunate RNG seed: bad_com should be different");
        assert!(!params.decommit(&msg, bf, bad_com));
    }

    #[test]
    fn commit_does_not_decommit_on_random_commit_g1() {
        commit_does_not_decommit_on_random_commit::<G1Projective>()
    }

    #[test]
    fn commit_does_not_decommit_on_random_commit_g2() {
        commit_does_not_decommit_on_random_commit::<G2Projective>()
    }
}
