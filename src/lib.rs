pub mod blinded_signatures;
pub mod signatures;

#[cfg(test)]
mod tests {
    use crate::signatures::{KeyPair, Message};
    use bls12_381 as BLS12;
    use ff::Field;

    #[test]
    fn make_keypair() {
        let mut rng = rand::thread_rng();
        let _kp = KeyPair::new(3, &mut rng);
    }

    #[test]
    fn signing_is_correct() {
        let mut rng = rand::thread_rng();
        let kp = KeyPair::new(3, &mut rng);
        let msg = Message::new(vec![
            BLS12::Scalar::random(&mut rng),
            BLS12::Scalar::random(&mut rng),
            BLS12::Scalar::random(&mut rng),
        ]);

        let sig = kp.try_sign(&mut rng, &msg).unwrap();
        if !kp.verify(&msg, &sig) {
            panic!("Signature didn't verify!!");
        }
    }
}
