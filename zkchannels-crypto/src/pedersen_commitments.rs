/*!
Pedersen commitments \[1\] over the prime-order pairing groups from BLS12-381 \[2\].

## References

1. Torben Pyrds Pedersen. "Non-interactive and information-theoretic secure verifiable secret sharing".
1992. URL: https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF

2. D. Boneh, S. Gorbunov, R. Wahby, H. Wee, and Z. Zhang. "BLS Signatures, Version 4". Internet-draft, IETF.
2021. URL: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
*/
use crate::{serde::*, types::*, Error};
use group::Group;
use serde::*;
use std::iter;

/// A Pedersen commitment to a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound = "G: SerializeElement")]
pub struct Commitment<G>(#[serde(with = "SerializeElement")] pub(crate) G)
where
    G: Group<Scalar = Scalar>;

/// Parameters for Pedersen commitments.
///
/// These are defined over the prime-order pairing groups from BLS12-381.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "G: SerializeG1")]
pub struct PedersenParameters<G>
where
    G: Group<Scalar = Scalar>,
{
    #[serde(with = "SerializeElement")]
    pub(crate) h: G,
    #[serde(with = "SerializeElement")]
    pub(crate) gs: Vec<G>,
}

impl<G: Group<Scalar = Scalar>> PedersenParameters<G> {
    /**
    Generate a new set of parameters for making commitments to messages of given
    length.

    These are chosen uniformly at random, such that no discrete logarithm relationships
    are known among the generators.
    */
    pub fn new(length: usize, rng: &mut impl Rng) -> Self {
        let h: G = random_non_identity(&mut *rng);
        let gs = iter::repeat_with(|| random_non_identity(&mut *rng))
            .take(length)
            .collect();
        Self { h, gs }
    }

    /// Commit to a message using the provided blinding factor.
    pub fn commit(&self, msg: &Message, bf: BlindingFactor) -> Result<Commitment<G>, Error> {
        if msg.len() != self.gs.len() {
            return Err(Error::MessageLengthMismatch {
                expected: self.gs.len(),
                got: msg.len(),
            });
        }

        let com: G = self.h * bf.0
            + self
                .gs
                .iter()
                .zip(msg.iter())
                .map(|(&g, m)| g * m)
                .sum::<G>();

        Ok(Commitment(com))
    }

    /// Verify a commitment to a message, using the given blinding factor
    pub fn decommit(
        &self,
        msg: &Message,
        bf: BlindingFactor,
        com: Commitment<G>,
    ) -> Result<bool, Error> {
        Ok(self.commit(msg, bf)? == com)
    }

    /// Return the message length that these parameters can commit to.
    pub fn message_len(&self) -> usize {
        self.gs.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ff::Field;

    fn commit_decommit<G: Group<Scalar = Scalar>>() -> Result<(), Error> {
        let mut rng = crate::test::rng();
        let length = 3;
        let params = PedersenParameters::<G>::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );
        let bf = BlindingFactor::new(&mut rng);

        let com = params.commit(&msg, bf)?;
        assert!(params.decommit(&msg, bf, com)?);

        Ok(())
    }

    #[test]
    fn commit_decommit_g1() -> Result<(), Error> {
        commit_decommit::<G1Projective>()
    }

    #[test]
    fn commit_decommit_g2() -> Result<(), Error> {
        commit_decommit::<G2Projective>()
    }

    fn commit_does_not_decommit_on_wrong_msg<G: Group<Scalar = Scalar>>() -> Result<(), Error> {
        let mut rng = crate::test::rng();
        let length = 3;
        let params = PedersenParameters::<G>::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );
        let bf = BlindingFactor::new(&mut rng);

        let bad_msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        assert_ne!(&*msg, &*bad_msg, "weird RNG: bad_msg should be different");

        let com = params.commit(&msg, bf)?;
        assert!(!params.decommit(&bad_msg, bf, com)?);

        Ok(())
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_msg_g1() -> Result<(), Error> {
        commit_does_not_decommit_on_wrong_msg::<G1Projective>()
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_msg_g2() -> Result<(), Error> {
        commit_does_not_decommit_on_wrong_msg::<G2Projective>()
    }

    fn commit_does_not_decommit_on_wrong_bf<G: Group<Scalar = Scalar>>() -> Result<(), Error> {
        let mut rng = crate::test::rng();
        let length = 3;
        let params = PedersenParameters::<G>::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );
        let bf = BlindingFactor::new(&mut rng);
        let bad_bf = BlindingFactor::new(&mut rng);

        assert_ne!(bf.0, bad_bf.0, "weird RNG: bad_bf should be different");

        let com = params.commit(&msg, bf)?;
        assert!(!params.decommit(&msg, bad_bf, com)?);

        Ok(())
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_bf_g1() -> Result<(), Error> {
        commit_does_not_decommit_on_wrong_bf::<G1Projective>()
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_bf_g2() -> Result<(), Error> {
        commit_does_not_decommit_on_wrong_bf::<G2Projective>()
    }

    fn commit_does_not_decommit_on_wrong_commit<G: Group<Scalar = Scalar>>() -> Result<(), Error> {
        let mut rng = crate::test::rng();
        let length = 3;
        let params = PedersenParameters::<G>::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );
        let bf = BlindingFactor::new(&mut rng);

        let bad_com = {
            let msg = Message::new(
                iter::repeat_with(|| Scalar::random(&mut rng))
                    .take(length)
                    .collect(),
            );
            params.commit(&msg, bf)?
        };

        let com = params.commit(&msg, bf)?;

        assert_ne!(com.0, bad_com.0, "weird RNG: bad_com should be different");
        assert!(!params.decommit(&msg, bf, bad_com)?);

        Ok(())
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_commit_g1() -> Result<(), Error> {
        commit_does_not_decommit_on_wrong_commit::<G1Projective>()
    }

    #[test]
    fn commit_does_not_decommit_on_wrong_commit_g2() -> Result<(), Error> {
        commit_does_not_decommit_on_wrong_commit::<G2Projective>()
    }

    #[test]
    fn commit_msg_must_be_correct_length() {
        let mut rng = crate::test::rng();
        let params = PedersenParameters::<G1Projective>::new(3, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(6)
                .collect(),
        );
        let bf = BlindingFactor::new(&mut rng);

        let _ = params
            .commit(&msg, bf)
            .expect_err("Commitment should fail with mismatched message length.");
    }
}
