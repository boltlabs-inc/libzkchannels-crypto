use rand::{thread_rng, SeedableRng};

// Seeded rng for replicable tests.
pub fn seeded_rng() -> (impl rand::CryptoRng + rand::RngCore) {
    const TEST_RNG_SEED: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
    rand::rngs::StdRng::from_seed(TEST_RNG_SEED)
}

#[allow(dead_code)] //probably because imported into signature_proofs and not used, and integration tests run as seperate crates
pub fn real_rng() -> (impl rand::CryptoRng + rand::RngCore) {
    thread_rng()
}
