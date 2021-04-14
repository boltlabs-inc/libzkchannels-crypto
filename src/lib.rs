pub mod blinded_signatures;
pub mod signatures;

#[cfg(test)]
mod tests {
    use crate::signatures::KeyPair;

    #[test]
    #[should_panic]
    fn make_keypair() {
        let _kp = KeyPair::new(3);
    }
}
