pub mod pedersen_commitments;
pub mod ps_blind_signatures;
pub mod ps_signatures;

mod types {
    use std::ops::Deref;

    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

    /// Fixed-length message type used in Pointcheval-Sanders schemes   
    #[derive(Debug, Clone)]
    pub struct Message(Vec<Scalar>);

    impl Deref for Message {
        type Target = [Scalar];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Message {
        pub fn new(m: Vec<Scalar>) -> Self {
            Message(m)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ps_signatures::KeyPair, types::Message};
    use bls12_381::Scalar;
    use ff::Field;
    use std::iter;

    #[test]
    fn make_keypair() {
        let mut rng = rand::thread_rng();
        let _kp = KeyPair::new(3, &mut rng);
    }

    #[test]
    fn signing_is_correct() {
        let mut rng = rand::thread_rng();
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
}
