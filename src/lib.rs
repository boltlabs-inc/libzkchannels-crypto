pub mod blinded_signatures;
pub mod signatures;

mod types {
    pub use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
}

#[cfg(test)]
mod tests {
    use crate::signatures::{KeyPair, Message};
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
