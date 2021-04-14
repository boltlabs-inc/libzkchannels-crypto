pub mod blinded_signatures;
pub mod signatures;

#[cfg(test)]
mod tests {
    use crate::signatures::KeyPair;

    #[test]
    fn make_keypair() {
        let mut rng = rand::thread_rng();
        let _kp = KeyPair::new(3, &mut rng);
    }
}
