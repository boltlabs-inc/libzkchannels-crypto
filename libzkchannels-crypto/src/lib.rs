pub mod pedersen_commitments;
pub mod ps_blind_signatures;
pub mod ps_keys;
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
