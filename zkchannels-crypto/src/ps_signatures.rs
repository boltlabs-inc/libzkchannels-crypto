//! Randomizable multi-message Pointcheval-Sanders signatures over BLS12-381.
//!
//! The signature scheme used is defined in the 2016 paper, ["Short randomizable signatures"]
//! (https://eprint.iacr.org/2015/525.pdf); The BLS12-381 curve is defined in the (now expired) IRTF
//! draft titled ["BLS
//! Signatures"](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).
use crate::{ps_keys::*, serde::*, types::*};
use ff::Field;
use serde::*;

/// A `Signer` may be used to sign a message.
pub trait Signer {
    /// Try to sign a message. Fails if the keypair caller length does not match message length.
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message) -> Result<Signature, String>;
}

/// A `Verifier` may be used to verify a message.
pub trait Verifier {
    /// Verify a signature on a given message.
    fn verify(&self, msg: &Message, sig: &Signature) -> bool;
}

/// A signature on a message, generated using Pointcheval-Sanders.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Signature {
    /**
    First part of a signature.

    In some papers, this is denoted `h`.
    */
    #[serde(with = "SerializeElement")]
    pub(crate) sigma1: G1Affine,
    /**
    Second part of a signature.

    In some papers, this is denoted `H`.
    */
    #[serde(with = "SerializeElement")]
    pub(crate) sigma2: G1Affine,
}

impl Signature {
    /// Randomize a signature in place.
    pub fn randomize(&mut self, rng: &mut impl Rng) {
        let r = Scalar::random(rng);
        *self = Signature {
            sigma1: (self.sigma1 * r).into(),
            sigma2: (self.sigma2 * r).into(),
        };
    }

    /// Convert to a bytewise representation
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut buf: [u8; 96] = [0; 96];
        buf[..48].copy_from_slice(&self.sigma1.to_compressed());
        buf[48..].copy_from_slice(&self.sigma2.to_compressed());
        buf
    }

    /**
    Check whether the signature is well-formed.

    This checks that first element is not the identity element. This implementation uses only
    checked APIs to ensure that both parts of the signature are in the expected group (G1).
    */
    pub fn is_well_formed(&self) -> bool {
        !bool::from(self.sigma1.is_identity())
    }
}

impl Signer for SecretKey {
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message) -> Result<Signature, String> {
        if self.ys.len() != msg.len() {
            return Err(format!(
                "Message is incorrect length ({}, expected {})",
                msg.len(),
                self.ys.len()
            ));
        }
        // select h randomly from G1*.
        let h: G1Projective = random_non_identity(&mut *rng);

        // [x] + sum( [yi] * [mi] ), for the secret key ([x], [y1], ...) and message [m1] ...
        let scalar_combination = self.x
            + self
                .ys
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<Scalar>();

        Ok(Signature {
            sigma1: h.into(),
            // sigma2 = h * [scalar_combination]
            sigma2: (h * scalar_combination).into(),
        })
    }
}

impl Verifier for PublicKey {
    fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        if !sig.is_well_formed() {
            return false;
        }

        // x + sum( yi * [mi] ), for the public key (x, y1, ...) and message [m1], [m2]...
        let lhs = self.x2
            + self
                .y2s
                .iter()
                .zip(msg.iter())
                .map(|(yi, mi)| yi * mi)
                .sum::<G2Projective>();

        let verify_pairing = pairing(&sig.sigma1, &lhs.into());
        let signature_pairing = pairing(&sig.sigma2, &self.g2);

        verify_pairing == signature_pairing
    }
}

impl Signer for KeyPair {
    fn try_sign(&self, rng: &mut impl Rng, msg: &Message) -> Result<Signature, String> {
        self.secret_key().try_sign(rng, msg)
    }
}

impl Verifier for KeyPair {
    fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        self.public_key().verify(msg, sig)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter;

    #[test]
    fn verify_signed_message() {
        let mut rng = crate::test::rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let sig = kp.try_sign(&mut rng, &msg).unwrap();

        assert!(
            kp.verify(&msg, &sig),
            "Signature didn't verify!! {:?}, {:?}",
            kp,
            msg
        );
    }

    #[test]
    fn fail_verification_of_different_message() {
        let mut rng = crate::test::rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let sig = kp.try_sign(&mut rng, &msg).unwrap();
        let bad_msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        assert_ne!(
            &*msg, &*bad_msg,
            "RNG failed to generate a different message."
        );
        assert!(
            !kp.verify(&bad_msg, &sig),
            "Signature verified on the wrong message!",
        );
    }

    #[test]
    fn fail_mismatched_message_length() {
        let mut rng = crate::test::rng();
        let kp = KeyPair::new(1, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(10)
                .collect(),
        );

        let _ = kp
            .try_sign(&mut rng, &msg)
            .expect_err("Signing should fail with mismatched message length");
    }

    #[test]
    fn fail_verification_with_wrong_keypair() {
        let mut rng = crate::test::rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let bad_kp = KeyPair::new(length, &mut rng);
        let bad_sig = bad_kp.try_sign(&mut rng, &msg).unwrap();

        assert!(
            !kp.verify(&msg, &bad_sig),
            "Signature from a different keypair verified!",
        );
    }

    #[test]
    fn fail_unit_signature() {
        let mut rng = crate::test::rng();
        let length = 3;
        let kp = KeyPair::new(length, &mut rng);
        let msg = Message::new(
            iter::repeat_with(|| Scalar::random(&mut rng))
                .take(length)
                .collect(),
        );

        let bad_sig = Signature {
            sigma1: G1Affine::identity(),
            sigma2: G1Projective::random(&mut rng).into(),
        };

        assert!(
            !kp.verify(&msg, &bad_sig),
            "Bad signature with sigma1 = 1 verified!"
        );
    }
}
