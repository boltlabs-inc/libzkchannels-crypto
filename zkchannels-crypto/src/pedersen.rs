//! Pedersen commitments \[1\] over the prime-order pairing groups from BLS12-381 \[2\].
//!
//! Commitments may be formed using the [`commit`] method on a [`Message`] and verified with the
//! [`verify_opening`] method on a [`Commitment`].
//! methods. [`PedersenParameters`] may be constructed by uniform random sampling from an [`Rng`],
//! using the [`PedersenParameters::new`] method.
//! ```
//! # use zkchannels_crypto::{BlindingFactor, Message, pedersen::PedersenParameters};
//! # use bls12_381::G1Projective;
//! # let mut rng = rand::thread_rng();
//! let params = PedersenParameters::<G1Projective, 5>::new(&mut rng);
//! let msg = Message::<5>::random(&mut rng);
//! let bf = BlindingFactor::new(&mut rng);
//! let commitment = msg.commit(&params, bf);
//! assert!(commitment.verify_opening(&params, bf, &msg));
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
//! [`commit`]: Message::commit
//! [`verify_opening`]: Commitment::verify_opening
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
pub struct Commitment<G>(#[serde(with = "SerializeElement")] pub(crate) G)
where
    G: Group<Scalar = Scalar>;

impl<G: Group<Scalar = Scalar>> Commitment<G> {
    /// Form a commit to a message and blinding factor using the given parameters.
    pub(crate) fn new<const N: usize>(
        msg: &Message<N>,
        pedersen_params: &PedersenParameters<G, N>,
        bf: BlindingFactor,
    ) -> Self {
        let com: G =
            *pedersen_params.h() * bf.as_scalar() + inner_product(pedersen_params.gs(), msg);

        Commitment(com)
    }

    /// Verify a provided opening of the commitment.
    pub fn verify_opening<const N: usize>(
        &self,
        pedersen_params: &PedersenParameters<G, N>,
        bf: BlindingFactor,
        msg: &Message<N>,
    ) -> bool {
        msg.commit(pedersen_params, bf) == *self
    }

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
/// Uses Box to avoid stack overflows with large parameter sets.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "G: SerializeG1")]
pub struct PedersenParameters<G, const N: usize>
where
    G: Group<Scalar = Scalar>,
{
    #[serde(with = "SerializeElement")]
    h: G,
    #[serde(with = "SerializeElement")]
    gs: Box<[G; N]>,
}

#[cfg(feature = "sqlite")]
crate::impl_sqlx_for_bincode_ty!(PedersenParameters<G1Projective, 1>);

impl<G: Group<Scalar = Scalar>, const N: usize> PedersenParameters<G, N> {
    /// Generate a new, random set of Pedersen parameters.
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
        Self {
            h,
            gs: Box::new(gs),
        }
    }

    /// Produce Pedersen parameters from a set of known generators.
    ///
    /// In general, if these generators are derived from a more complex type we recommend using
    /// an instantiation of `IntoPedersenParameters` rather than calling this directly. This avoids
    /// errors caused by deriving the generators inconsistently across different calls.
    pub fn from_generators(h: G, gs: [G; N]) -> PedersenParameters<G, N> {
        Self {
            h,
            gs: Box::new(gs),
        }
    }

    pub(crate) fn h(&self) -> &G {
        &self.h
    }

    pub(crate) fn gs(&self) -> &[G; N] {
        self.gs.as_ref()
    }
}

/// Set of things that can be converted (deterministically) into [`PedersenParameters`].
pub trait ToPedersenParameters<G: Group<Scalar = Scalar>, const N: usize> {
    /// Generate [`PedersenParameters`] based on self.
    fn to_pedersen_parameters(&self) -> PedersenParameters<G, N>;
}

impl<G: Group<Scalar = Scalar>, const N: usize> ToPedersenParameters<G, N> for String {
    /// Produce Pedersen parameters using a hash-to-curve algorithm on a string.
    fn to_pedersen_parameters(&self) -> PedersenParameters<G, N> {
        todo!()
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeInput
    for PedersenParameters<G, N>
{
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume_bytes(self.h.to_bytes());
        for g in &*self.gs {
            builder.consume_bytes(g.to_bytes());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn commit_open<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let com = msg.commit(&params, bf);
        assert!(com.verify_opening(&params, bf, &msg));
    }

    #[test]
    fn commit_open_g1() {
        commit_open::<G1Projective>()
    }

    #[test]
    fn commit_open_g2() {
        commit_open::<G2Projective>()
    }

    fn commit_does_not_open_on_wrong_msg<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let bad_msg = Message::random(&mut rng);

        assert_ne!(
            &*msg, &*bad_msg,
            "unfortunate RNG seed: bad_msg should be different"
        );

        let com = msg.commit(&params, bf);
        assert!(!com.verify_opening(&params, bf, &bad_msg));
    }

    #[test]
    fn commit_does_not_open_on_wrong_msg_g1() {
        commit_does_not_open_on_wrong_msg::<G1Projective>()
    }

    #[test]
    fn commit_does_not_open_on_wrong_msg_g2() {
        commit_does_not_open_on_wrong_msg::<G2Projective>()
    }

    fn commit_does_not_open_on_wrong_bf<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);
        let bad_bf = BlindingFactor::new(&mut rng);

        assert_ne!(
            bf.0, bad_bf.0,
            "unfortunate RNG seed: bad_bf should be different"
        );

        let com = msg.commit(&params, bf);
        assert!(!com.verify_opening(&params, bad_bf, &msg));
    }

    #[test]
    fn commit_does_not_open_on_wrong_bf_g1() {
        commit_does_not_open_on_wrong_bf::<G1Projective>()
    }

    #[test]
    fn commit_does_not_open_on_wrong_bf_g2() {
        commit_does_not_open_on_wrong_bf::<G2Projective>()
    }

    fn commit_does_not_open_on_wrong_commit<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let bad_com = {
            let msg = Message::random(&mut rng);
            msg.commit(&params, bf)
        };

        let com = msg.commit(&params, bf);

        assert_ne!(
            com.0, bad_com.0,
            "unfortunate RNG seed: bad_com should be different"
        );
        assert!(!bad_com.verify_opening(&params, bf, &msg));
    }

    #[test]
    fn commit_does_not_open_on_wrong_commit_g1() {
        commit_does_not_open_on_wrong_commit::<G1Projective>()
    }

    #[test]
    fn commit_does_not_open_on_wrong_commit_g2() {
        commit_does_not_open_on_wrong_commit::<G2Projective>()
    }

    fn commit_does_not_open_on_random_commit<G: Group<Scalar = Scalar>>() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G, 3>::new(&mut rng);
        let msg = Message::random(&mut rng);
        let bf = BlindingFactor::new(&mut rng);

        let bad_com = Commitment::<G>(G::random(&mut rng));

        let com = msg.commit(&params, bf);

        assert_ne!(
            com.0, bad_com.0,
            "unfortunate RNG seed: bad_com should be different"
        );
        assert!(!bad_com.verify_opening(&params, bf, &msg));
    }

    #[test]
    fn commit_does_not_open_on_random_commit_g1() {
        commit_does_not_open_on_random_commit::<G1Projective>()
    }

    #[test]
    fn commit_does_not_open_on_random_commit_g2() {
        commit_does_not_open_on_random_commit::<G2Projective>()
    }
}
